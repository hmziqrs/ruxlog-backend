//! Shared OAuth (Facebook / GitHub / Apple) plumbing.
//!
//! Each provider module under `crate::modules::{facebook,github,apple}_auth_v1`
//! owns its IdP-specific HTTP (authorize URL, token exchange, userinfo / id_token
//! verification). The cross-cutting pieces — session-bound CSRF/PKCE state,
//! post-login redirect origin validation, user resolution + linking, and server
//! session creation — live here so the provider modules stay thin and the
//! security invariants (state single-use, email-verified gate, session-mapping
//! for revocation) are applied identically for every provider.
//!
//! Compiled only under the `auth-oauth` feature (the service module declaration
//! in `services/mod.rs` is feature-gated), matching `google_auth_v1`.

pub mod login;
pub mod redirect;
pub mod state;

pub use login::{find_or_create_user_for_oauth, finish_oauth_login, generate_oauth_nonce};
pub use redirect::build_allowed_success_redirect;
pub use state::{consume_oauth_state, oauth_session_id, store_oauth_state, ConsumedOauthState};
