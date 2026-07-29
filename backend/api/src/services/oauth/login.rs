//! Shared post-exchange finish logic for all third-party OAuth providers.
//!
//! Resolves a verified IdP identity to a local `users` row (looking up an
//! existing link, linking onto a matching email-verified account, or creating a
//! new pre-verified account), then starts a server session exactly the way the
//! password-login path does (`AuthBackend` + `user_sessions` row + tower-session
//! mapping). Mirrors `google_auth_v1::controller::finish_google_login`, minus
//! the Google-specific id_token JWKS step (each provider service does its own
//! identity verification before calling into here).

use sea_orm::{ActiveModelTrait, Set};
use tracing::{error, info, instrument, warn};

use crate::{
    db::sea_models::{user, user_oauth_identity, user_session},
    error::{ErrorCode, ErrorResponse},
    services::auth::AuthSession,
    AppState,
};

use user_oauth_identity::NewOauthIdentity;

/// Resolve a verified provider identity to a local user, applying the same
/// OAUTH-CREATE-UNVERIFIED / link-safety gates as the Google path:
///
/// 1. **Already linked** → return that user (login existing).
/// 2. **Existing user with the same email** → link the identity onto it, but
///    ONLY if the IdP asserted the email is verified. Otherwise refuse: an
///    attacker controlling an unverified-at-IdP account with the victim's email
///    must not take over the account, and we do NOT create a duplicate.
/// 3. **No matching user** → create a new pre-verified account, but ONLY if the
///    IdP verified the email. Otherwise refuse (the user signs up via normal
///    email verification).
///
/// `email_verified = true` is a hard precondition for both the link and create
/// branches; providers that cannot assert email verification must be configured
/// to refuse at the service layer before reaching here.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(state), fields(provider = %provider, provider_user_id = %provider_user_id, email = %email))]
pub async fn find_or_create_user_for_oauth(
    state: &AppState,
    provider: &str,
    provider_user_id: &str,
    email: String,
    name: String,
    email_verified: bool,
) -> Result<user::Model, ErrorResponse> {
    // 1. Already linked → log that user in directly.
    if let Some(identity) =
        user_oauth_identity::Entity::find_by_provider(&state.sea_db, provider, provider_user_id)
            .await?
    {
        let user = user::Entity::find_by_id_with_404(&state.sea_db, identity.user_id).await?;
        info!(
            user_id = user.id,
            "Existing user found by OAuth identity link"
        );
        return Ok(user);
    }

    // 2. Existing local user with the same email → link (IdP-verified gate).
    if let Some(existing) = user::Entity::find_by_email(&state.sea_db, email.clone()).await? {
        if !email_verified {
            warn!(user_id = existing.id, email = %email, "Refusing to link OAuth account: IdP email is not verified");
            return Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
                .with_message("Unable to link this account"));
        }
        info!(
            user_id = existing.id,
            "Linking OAuth account to existing user"
        );
        link_identity(&state.sea_db, existing.id, provider, provider_user_id).await?;
        return Ok(existing);
    }

    // 3. No existing user → create (IdP-verified gate, same rationale as Google).
    if !email_verified {
        warn!(email = %email, "Refusing to create account from OAuth: IdP email is not verified");
        return Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("The provider has not verified this email address"));
    }

    info!("Creating new user from OAuth account");
    let now = chrono::Utc::now().fixed_offset();
    let active = user::ActiveModel {
        name: Set(name),
        email: Set(email),
        password: Set(None),
        oauth_provider: Set(Some(provider.to_string())),
        role: Set(user::UserRole::User),
        is_verified: Set(true), // IdP-verified email ⇒ pre-verified locally
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    let user = active.insert(&state.sea_db).await.map_err(|e| {
        error!(error = ?e, "Failed to create user from OAuth");
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Failed to create user account")
    })?;

    link_identity(&state.sea_db, user.id, provider, provider_user_id).await?;
    tracing::Span::current().record("user_id", user.id);
    Ok(user)
}

/// Insert a `user_oauth_identities` link row for an already-resolved user.
async fn link_identity(
    db: &sea_orm::DatabaseConnection,
    user_id: i32,
    provider: &str,
    provider_user_id: &str,
) -> Result<(), ErrorResponse> {
    let now = chrono::Utc::now().fixed_offset();
    user_oauth_identity::Entity::link(
        db,
        NewOauthIdentity {
            user_id,
            provider: provider.to_string(),
            provider_user_id: provider_user_id.to_string(),
            created_at: now,
        },
    )
    .await
    .map(|_| ())
}

/// Start a server session for an OAuth-authenticated user: `auth.login`,
/// record a `user_sessions` row (device label = "<Provider> OAuth"), then
/// record the PG-row → tower-session-id mapping so the session can later be
/// revoked via `sessions_terminate` (mirrors the password + Google paths).
pub async fn finish_oauth_login(
    state: &AppState,
    auth: &mut AuthSession,
    user: &user::Model,
    provider_label: &str,
) -> Result<(), ErrorResponse> {
    auth.login(user).await.map_err(|e| {
        error!(error = %e, user_id = user.id, "Failed to create OAuth session");
        ErrorResponse::new(ErrorCode::InternalServerError).with_message("Failed to create session")
    })?;

    let session_row = user_session::Entity::create(
        &state.sea_db,
        user_session::NewUserSession::new(user.id, Some(format!("{provider_label} OAuth")), None),
    )
    .await
    .ok();

    // V-HIGH-2: record the PG-row → tower-session-id mapping so
    // `sessions_terminate` can later DEL the live tower-session record.
    // `auth.login` cycles the session id, so save first to materialize it.
    if (auth.session().save().await).is_ok() {
        if let (Some(row), Some(tower_sid)) = (session_row.as_ref(), auth.session().id()) {
            crate::services::auth::record_session_mapping(
                &state.redis_pool,
                row.id,
                &tower_sid.to_string(),
            )
            .await;
        }
    }

    Ok(())
}

/// Cryptographically-random OIDC nonce for providers that issue a signed
/// `id_token` (Apple). 128 bits of entropy (base64url ≈ 22 chars).
pub fn generate_oauth_nonce() -> String {
    use base64::Engine;
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
