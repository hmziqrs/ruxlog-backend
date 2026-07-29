//! Mail webhook receiver + admin suppression-list management.
//!
//! - `POST /mail/v1/webhook/{provider}` (public, CSRF-exempt) — receives an
//!   operator-owned bounce/complaint event (a Cloudflare Worker consuming the
//!   Email Service event Queue, HMAC-signed), verifies it, dedups for 24h, and
//!   upserts a suppression row. Cloudflare does NOT natively POST signed email
//!   events, so this receiver authenticates an envelope our reference Worker
//!   emits under a shared secret.
//! - `GET/POST/DELETE /mail/v1/suppression` (admin-only, always-on) — manage the
//!   suppression list by hand. Always-on so SMTP-only deployments can clear
//!   stale rows too.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use bytes::Bytes;
use serde_json::json;

use crate::{
    db::sea_models::email_suppression::{
        Entity as SuppressionEntity, NewSuppression, SuppressionQuery,
    },
    error::{ErrorCode, ErrorResponse},
    AppState,
};

use super::validator::{V1CreateSuppression, V1DeleteSuppression, V1ListSuppressionsQuery};

// Imports used only by the `mail-cloudflare` webhook receiver.
#[cfg(feature = "mail-cloudflare")]
use {
    crate::{
        db::sea_models::email_suppression::{SuppressionReason, SuppressionUpsert},
        services::{mail::provider::WebhookEvent},
    },
    sha2::{Digest, Sha256},
};

// ── Admin suppression CRUD ────────────────────────────────────────────────

/// List suppression entries (filter by reason/permanent/search, paginated).
pub async fn list_suppressions(
    State(state): State<AppState>,
    Query(q): Query<V1ListSuppressionsQuery>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let query = SuppressionQuery {
        page: q.page,
        reason: q.reason,
        permanent: q.permanent,
        search: q.search,
    };
    let result = SuppressionEntity::find_with_query(&state.sea_db, query).await?;
    Ok(Json(
        json!({ "data": result.data, "total": result.total, "page": result.page, "per_page": result.per_page }),
    ))
}

/// Manually add a recipient to the suppression list.
pub async fn create_suppression(
    State(state): State<AppState>,
    Json(payload): Json<V1CreateSuppression>,
) -> Result<(StatusCode, Json<serde_json::Value>), ErrorResponse> {
    let reason = payload.reason_or_default();
    let model = SuppressionEntity::create(
        &state.sea_db,
        NewSuppression {
            recipient: payload.recipient,
            reason,
            source: Some("admin".to_string()),
            diagnostic: payload.diagnostic,
            permanent: payload.permanent,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": model.id, "recipient": model.recipient, "permanent": model.permanent })),
    ))
}

/// Remove a recipient from the suppression list. `removed` is false if there was
/// nothing to delete.
pub async fn delete_suppression(
    State(state): State<AppState>,
    Query(q): Query<V1DeleteSuppression>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let recipient = q.recipient.trim().to_lowercase();
    if recipient.is_empty() {
        return Err(ErrorResponse::new(ErrorCode::InvalidEmailFormat)
            .with_message("recipient query param is required"));
    }
    let removed = SuppressionEntity::delete_by_recipient(&state.sea_db, &recipient).await?;
    Ok(Json(json!({ "removed": removed, "recipient": recipient })))
}

// ── Inbound webhook ───────────────────────────────────────────────────────

/// Receive an operator-owned bounce/complaint/delivery event.
#[allow(unused_variables)]
pub async fn mail_webhook_receiver(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    #[cfg(feature = "mail-cloudflare")]
    {
        use crate::services::mail::MailProvider;

        let event = WebhookEvent {
            provider: provider.clone(),
            payload: body.to_vec(),
            headers,
            query: None,
        };

        let parsed = state.mailer.verify_webhook(event).await.map_err(|e| {
            // Generic client message — the raw MailError can echo internal config
            // detail; keep it server-side only.
            tracing::warn!(error = %e, "mail webhook verification failed");
            crate::services::mail::mail_error_to_response(&e)
        })?;

        // Apply FIRST, THEN claim the dedup key (at-least-once). If apply fails
        // (e.g. a transient DB blip returns 500) we have NOT claimed the dedup
        // key, so the Worker's retry re-processes the event instead of being
        // acknowledged as a duplicate and permanently lost. The upsert is
        // idempotent, so a genuine duplicate still converges to one row.
        apply_mail_event(&state, &parsed).await?;

        // Replay protection: record a successfully-processed event for 24h so a
        // Worker retry (duplicate delivery) is a cheap no-op. Best-effort on a
        // Redis blip — the upsert above is idempotent either way.
        let mut hasher = Sha256::new();
        hasher.update(body.as_ref());
        let dedup_key = format!(
            "mail:webhook:{}:{}",
            provider,
            hex::encode(hasher.finalize())
        );
        if !rux_request_gate::dedup_nx(&state.redis_pool, &dedup_key, 86_400).await {
            tracing::info!(%provider, "Duplicate mail webhook (already processed); acknowledging");
            return Ok(Json(json!({ "received": true, "duplicate": true })));
        }

        Ok(Json(json!({ "received": true })))
    }

    #[cfg(not(feature = "mail-cloudflare"))]
    {
        let _ = (state, provider, headers, body);
        Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("Mail webhooks are not enabled on this server"))
    }
}

/// Upsert a suppression row for bounce/complaint events; delivered is a metric
/// only.
#[cfg(feature = "mail-cloudflare")]
async fn apply_mail_event(
    state: &AppState,
    ev: &crate::services::mail::provider::ParsedMailEvent,
) -> Result<(), ErrorResponse> {
    use crate::services::mail::provider::canonical;

    // PII: log only the recipient domain, never the full address.
    let recipient_domain = ev.recipient.split('@').nth(1).unwrap_or("unknown");
    match ev.event_type.as_str() {
        canonical::BOUNCED => {
            tracing::info!(%recipient_domain, permanent = ev.permanent, "mail bounce event -> suppressing");
            SuppressionEntity::upsert(
                &state.sea_db,
                &ev.recipient,
                SuppressionUpsert {
                    reason: SuppressionReason::Bounce,
                    source: Some("mail-webhook".to_string()),
                    diagnostic: ev.diagnostic.clone(),
                    permanent: ev.permanent,
                },
            )
            .await?;
        }
        canonical::COMPLAINED => {
            tracing::info!(%recipient_domain, "mail complaint event -> suppressing (permanent)");
            SuppressionEntity::upsert(
                &state.sea_db,
                &ev.recipient,
                SuppressionUpsert {
                    reason: SuppressionReason::Complaint,
                    source: Some("mail-webhook".to_string()),
                    diagnostic: ev.diagnostic.clone(),
                    permanent: true,
                },
            )
            .await?;
        }
        canonical::DELIVERED => {
            tracing::debug!(%recipient_domain, "mail delivered event");
        }
        other => {
            tracing::warn!(event_type = %other, "unknown mail event type; ignoring");
        }
    }
    Ok(())
}
