//! rux-fcm: Firebase Cloud Messaging (HTTP v1) client.
//!
//! Provides:
//! - A Google service-account holder that mints and caches OAuth2 access tokens
//!   (RS256 JWT-bearer grant against the `firebase.messaging` scope).
//! - A small FCM v1 client that POSTs a `FcmMessage` to
//!   `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
//!
//! Mirrors the outbound-HTTP style used elsewhere in ruxlog: the caller threads
//! in a shared, timeout-configured `reqwest::Client` (see
//! `state::build_http_client`) so no handler thread can be pinned by a hanging
//! upstream.

pub mod auth;
pub mod client;
pub mod error;

pub use auth::{AccessToken, ServiceAccount};
pub use client::{FcmClient, FcmMessage, Notification};
pub use error::FcmError;
