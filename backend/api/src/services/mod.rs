// Always enabled
pub mod abuse_limiter;
pub mod auth;
pub mod mail;
pub mod paywall;
pub mod redis;
pub mod webhook_util;

// Feature-gated
#[cfg(feature = "image-optimization")]
pub mod image_optimizer;

#[cfg(feature = "admin-acl")]
pub mod acl_service;

#[cfg(feature = "admin-routes")]
pub mod route_blocker_config;

#[cfg(feature = "admin-routes")]
pub mod route_blocker_service;

#[cfg(feature = "seed-system")]
pub mod seed;

#[cfg(feature = "seed-system")]
pub mod seed_config;

#[cfg(feature = "billing")]
pub mod billing;

#[cfg(feature = "scheduler")]
pub mod scheduler;

// --- Services added for the issues batch (2026-07-27) ---
#[cfg(feature = "cache")]
pub mod api_cache;
#[cfg(feature = "cache")]
pub mod cache;
#[cfg(feature = "image-moderation")]
pub mod image_moderation;
#[cfg(feature = "notifications")]
pub mod notification;
#[cfg(feature = "auth-oauth")]
pub mod oauth;
#[cfg(feature = "auth-passkey")]
pub mod webauthn;
