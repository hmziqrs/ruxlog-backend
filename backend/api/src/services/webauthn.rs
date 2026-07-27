//! WebAuthn / passkey service (issue #4).
//!
//! Wraps [`webauthn_rs::Webauthn`] with the ruxlog DB layer. The RP
//! configuration is read from env at startup (`WEBAUTHN_RP_ID`,
//! `WEBAUTHN_RP_ORIGIN`, `WEBAUTHN_RP_NAME`) with safe localhost defaults so
//! dev/test boots without configuration; production MUST set the real RP id
//! (passkeys are origin-bound — a wrong RP id makes every registration /
//! authentication fail at the authenticator).
//!
//! Challenge / authentication STATE is held by the CLIENT (the simpler,
//! stateless option called out by the charter): `start_*` returns both the
//! challenge and the opaque state, both are echoed to the client, and
//! `finish_*` deserializes the state back. This is why `webauthn-rs` is built
//! with the `danger-allow-state-serialisation` feature — the state types
//! (`PasskeyRegistration`, `PasskeyAuthentication`) must be (de)serializable.
//! The state is cryptographically bound to the challenge it was minted with,
//! so a tampered or replayed state is rejected by the WebAuthn core.

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tracing::warn;
use webauthn_rs::prelude::*;

use crate::db::sea_models::{passkey_credential, user};
use crate::error::{ErrorCode, ErrorResponse};

/// Wraps the WebAuthn core with the ruxlog DB + user layer.
#[derive(Clone)]
pub struct WebauthnService {
    core: Arc<Webauthn>,
}

impl WebauthnService {
    /// Build the service from process env, with safe localhost defaults.
    pub fn from_env() -> Result<Self, ErrorResponse> {
        let rp_id = std::env::var("WEBAUTHN_RP_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "localhost".to_string());
        let rp_origin = std::env::var("WEBAUTHN_RP_ORIGIN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let rp_name = std::env::var("WEBAUTHN_RP_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Ruxlog".to_string());
        Self::new(&rp_id, &rp_origin, &rp_name)
    }

    /// Build the service from explicit RP parameters.
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: &str) -> Result<Self, ErrorResponse> {
        let origin = url::Url::parse(rp_origin).map_err(|e| {
            ErrorResponse::new(ErrorCode::ConfigurationError)
                .with_message(
                    "Invalid WEBAUTHN_RP_ORIGIN (expected a full URL like https://ruxlog.com)",
                )
                .with_details(e.to_string())
        })?;

        let builder = WebauthnBuilder::new(rp_id, &origin).map_err(map_webauthn_err)?;
        // `.rp_name(self)` consumes and returns the builder — rebind it rather
        // than calling it as a discarded statement (which would move it and
        // make the subsequent `.build()` a use-after-move).
        let builder = builder.rp_name(rp_name);
        let core = builder.build().map_err(map_webauthn_err)?;
        Ok(Self {
            core: Arc::new(core),
        })
    }

    // ── Registration (behind `verified`) ────────────────────────────────────

    /// Begin passkey registration for an authenticated user. Returns the
    /// challenge to hand to the authenticator AND the opaque registration
    /// state, which the client MUST echo back to `/register/finish` verbatim.
    pub fn start_registration(
        &self,
        user: &user::Model,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), ErrorResponse> {
        // The WebAuthn "user handle" must be a stable, opaque per-user id.
        // Derive a deterministic v5 UUID from the ruxlog user id so the same
        // user always presents the same handle (the authenticator binds the
        // credential to this handle on registration and returns it on
        // discoverable login). We do NOT use the integer id directly because
        // WebAuthn requires the handle be a byte string with low correlation
        // to a public identifier — a hashed namespace UUID gives that.
        let user_uuid = user_handle_for(user.id);
        let (challenge, state) = self
            .core
            .start_passkey_registration(user_uuid, &user.email, &user.name, None)
            .map_err(map_webauthn_err)?;
        Ok((challenge, state))
    }

    /// Finish passkey registration: verify the authenticator's response, then
    /// persist the resulting [`Passkey`]. `device_type` / `transports` are
    /// optional client-supplied labels stored alongside the credential.
    pub async fn finish_registration(
        &self,
        db: &DatabaseConnection,
        user_id: i32,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
        device_type: Option<String>,
        transports: Option<serde_json::Value>,
    ) -> Result<passkey_credential::Model, ErrorResponse> {
        let passkey = self
            .core
            .finish_passkey_registration(reg, state)
            .map_err(map_webauthn_err)?;
        passkey_credential::Entity::create(db, user_id, &passkey, device_type, transports).await
    }

    // ── Authentication (behind `unauthenticated`, discoverable) ─────────────

    /// Begin a discoverable passkey login. No user is identified up front —
    /// the authenticator returns the credential id, which we resolve to a user
    /// in `finish_login`. An empty allowed-credentials list tells the
    /// authenticator any of the user's resident/discoverable passkeys may be
    /// used (the passkey UX: no username field).
    pub fn start_login(
        &self,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), ErrorResponse> {
        let (challenge, state) = self
            .core
            .start_passkey_authentication(&[])
            .map_err(map_webauthn_err)?;
        Ok((challenge, state))
    }

    /// Finish a discoverable passkey login: verify the assertion, resolve the
    /// credential to a user, enforce signature-counter clone detection, then
    /// advance the stored counter. Returns the credential row and its user so
    /// the controller can issue the session (mirroring the password login
    /// path: ban re-check + `login_with_metadata` + `user_sessions` row).
    pub async fn finish_login(
        &self,
        db: &DatabaseConnection,
        cred: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<(passkey_credential::Model, user::Model), ErrorResponse> {
        let result = self
            .core
            .finish_passkey_authentication(cred, state)
            .map_err(map_webauthn_err)?;

        // Passkeys require User Verification (UV). A credential that asserted
        // without UV is not behaving as a passkey — reject.
        if !result.user_verified() {
            warn!("passkey login rejected: user_verified is false");
            return Err(
                ErrorResponse::new(ErrorCode::Unauthorized).with_message("Authentication failed")
            );
        }

        // Resolve the credential to its row by the returned credential id.
        // `AuthenticationResult`'s fields are `pub(crate)` in webauthn-rs-core,
        // so we go through the public accessors (`cred_id()`, `counter()`).
        let credential_id = passkey_credential::encode_credential_id(result.cred_id().as_slice());
        let stored = passkey_credential::Entity::find_by_credential_id(db, &credential_id)
            .await?
            .ok_or_else(|| {
                warn!(credential_id = %credential_id, "passkey login: unknown credential id");
                ErrorResponse::new(ErrorCode::Unauthorized).with_message("Authentication failed")
            })?;

        // Clone detection (WebAuthn spec, §6.1.17): if the authenticator
        // reports non-zero counters, each new assertion MUST advance the
        // counter. A counter that did not advance (or went backwards)
        // indicates the credential may have been cloned — refuse the login.
        // Authenticators that do not support counters always report 0; we
        // cannot enforce monotonicity in that case, so 0 is exempt.
        let counter = result.counter();
        if counter != 0 && (counter as i64) <= stored.counter {
            warn!(
                credential_id = %stored.credential_id,
                user_id = stored.user_id,
                stored_counter = stored.counter,
                asserted_counter = counter,
                "passkey login rejected: signature counter did not advance (possible cloned credential)"
            );
            return Err(
                ErrorResponse::new(ErrorCode::Unauthorized).with_message("Authentication failed")
            );
        }

        // Resolve the owning user.
        let user_model = user::Entity::get_by_id(db, stored.user_id)
            .await?
            .ok_or_else(|| {
                warn!(
                    user_id = stored.user_id,
                    "passkey login: credential points at missing user"
                );
                ErrorResponse::new(ErrorCode::Unauthorized).with_message("Authentication failed")
            })?;

        // Advance the stored counter + last_used_at (clone-detection watermark).
        passkey_credential::Entity::touch_counter(db, stored.id, counter).await?;

        Ok((stored, user_model))
    }
}

/// Map a `WebauthnError` to a generic auth-failure `ErrorResponse`. We never
/// surface the library's specific error text to the client (it could leak
/// whether the failure was the challenge, the state, or the signature),
/// matching the 2FA / login-totp endpoints' generic InvalidToken pattern.
fn map_webauthn_err(err: WebauthnError) -> ErrorResponse {
    warn!(error = ?err, "WebAuthn operation failed");
    ErrorResponse::new(ErrorCode::InvalidToken).with_message("WebAuthn operation failed")
}

/// Derive a stable, opaque WebAuthn user handle (UUID) from a ruxlog user id.
/// The handle is namespaced + hashed so it has no correlation with the public
/// integer id, but is fully deterministic so the same user always presents the
/// same handle.
///
/// We assemble the UUID from a SHA-256 digest manually rather than calling
/// `Uuid::new_v5` because the `uuid` crate in this workspace is built WITHOUT
/// the `v5` feature (see `Cargo.toml`: `uuid = { ..., features = ["v4",
/// "fast-rng"] }`). SHA-256 comes from the already-present `sha2` dep. The
/// version/variant bits are set so the UUID is well-formed, but WebAuthn
/// treats the handle as an opaque byte string regardless.
fn user_handle_for(user_id: i32) -> Uuid {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"ruxlog:user:");
    hasher.update(user_id.to_be_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 version (5, name-based) + variant (RFC 4122) bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Uuid::from_bytes(bytes)
}
