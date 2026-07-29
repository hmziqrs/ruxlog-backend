use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_client_ip::ClientIp;
use axum_macros::debug_handler;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    db::sea_models::newsletter_subscriber::{
        Column as SubscriberColumn, Entity as SubscriberEntity, NewSubscriber, SubscriberStatus,
    },
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    services::{
        abuse_limiter::{limiter, AbuseLimiterConfig},
        auth::AuthSession,
    },
    AppState,
};

use super::validator::{
    V1ListSubscribersQuery, V1SendNewsletterPayload, V1SubscribePayload, V1UnsubscribePayload,
};

/// Pace between newsletter sends to stay under the provider per-minute quota
/// (MAIL_PROVIDER_CFG defaults to 50/min → ~1.3s keeps us under it without a
/// burst that trips the temp block).
const NEWSLETTER_PACE: std::time::Duration = std::time::Duration::from_millis(1300);
/// How many times to back off + retry a single recipient when the provider
/// quota bucket throttles it before counting the send as failed.
const NEWSLETTER_MAX_THROTTLE_RETRIES: u8 = 2;

async fn send_mail(
    mailer: &crate::services::mail::MailRouter,
    to_email: &str,
    subject: &str,
    html: Option<&str>,
    text: Option<&str>,
) -> Result<(), crate::services::mail::MailError> {
    use crate::services::mail::{provider::TEMPLATE_NEWSLETTER, MailProvider, OutboundEmail};

    let msg = OutboundEmail {
        to: to_email.to_string(),
        subject: subject.to_string(),
        html: html.map(|s| s.to_string()),
        text: text.map(|s| s.to_string()),
        template: Some(TEMPLATE_NEWSLETTER),
    };
    mailer.send(msg).await.map(|_| ())
}

#[debug_handler]
#[instrument(skip(state, client_ip, payload), fields(email = %payload.email))]
pub async fn subscribe(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    payload: ValidatedJson<V1SubscribePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let email = payload.email.trim().to_lowercase();
    let token = Uuid::new_v4().to_string();

    // Abuse limiter: per-email subscription attempts
    let key = format!("newsletter:subscribe:{}", email);
    let config = AbuseLimiterConfig {
        temp_block_attempts: 5,
        temp_block_range: 60,
        temp_block_duration: 60 * 60,
        block_retry_limit: 20,
        block_range: 24 * 60 * 60,
        block_duration: 24 * 60 * 60,
    };
    limiter(&state.redis_pool, &key, config).await?;

    // DOS-NEWSLETTER-IP-1: per-IP bucket. The per-email limiter above is
    // defeated by rotating the email field; pair it with a per-IP bucket so a
    // single source cannot flood inserts + outbound confirmation mail.
    limiter(
        &state.redis_pool,
        &format!("newsletter:subscribe:ip:{client_ip}"),
        AbuseLimiterConfig {
            temp_block_attempts: 20,
            temp_block_range: 60,
            temp_block_duration: 60 * 60,
            block_retry_limit: 200,
            block_range: 24 * 60 * 60,
            block_duration: 24 * 60 * 60,
        },
    )
    .await?;

    let new_sub = NewSubscriber {
        email: email.clone(),
        status: SubscriberStatus::Pending,
        token: token.clone(),
    };

    match SubscriberEntity::create(&state.sea_db, new_sub).await {
        Ok(_model) => {
            info!(email = %email, "Newsletter subscription created");
            let site_url = state.settings.site.url.clone();

            // CRYP-GAP-012 / CRYP-RNG-005: do NOT carry the secret token in the
            // URL query string (`?token=`), where it leaks into access logs,
            // proxy logs, and the Referer header. Put it in the URL *fragment*
            // (`#token=`) instead — fragments are never transmitted to servers.
            // The client reads the fragment and POSTs `{email, token}` in the
            // JSON body (the /confirm endpoint already accepts a JSON body).
            // Token strength is unchanged: 122 bits of UUIDv4 entropy.
            let confirm_url = format!(
                "{}/newsletter/confirm#email={}&token={}",
                site_url.trim_end_matches('/'),
                urlencoding::encode(&email),
                urlencoding::encode(&token)
            );

            let subject = "Confirm your subscription";
            let html = format!(
                "<p>Thanks for subscribing!</p><p>Please confirm your subscription by clicking the link below:</p><p><a href=\"{0}\">{0}</a></p>",
                confirm_url
            );
            // Best-effort email; do not fail subscription on send error
            let _ = send_mail(&state.mailer, &email, subject, Some(&html), None).await;

            // The token / confirm_url are intentionally NOT echoed in the
            // response body, even in debug builds, to avoid leaking the secret
            // token into client logs.
            let body = json!({ "message": "Please check your email to confirm your subscription" });
            Ok((StatusCode::CREATED, Json(body)))
        }
        Err(err) => {
            error!(email = %email, "Failed to create newsletter subscription: {}", err);
            Err(err)
        }
    }
}

#[debug_handler]
#[instrument(skip(state, payload), fields(email = %payload.email))]
pub async fn unsubscribe(
    State(state): State<AppState>,
    payload: ValidatedJson<V1UnsubscribePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let email = payload.email.trim().to_lowercase();
    let token = payload.token.trim().to_string();

    match SubscriberEntity::unsubscribe(&state.sea_db, &email, Some(&token)).await {
        Ok(Some(_)) => {
            info!(email = %email, "Newsletter unsubscribed");
            Ok(Json(json!({ "message": "Unsubscribed successfully" })))
        }
        Ok(None) => {
            warn!(email = %email, "Invalid unsubscribe token");
            Err(ErrorResponse::new(ErrorCode::SubscriberNotFound)
                .with_message("Invalid token or subscriber not found"))
        }
        Err(err) => {
            error!(email = %email, "Failed to unsubscribe: {}", err);
            Err(err)
        }
    }
}

#[debug_handler]
#[instrument(skip(state, _auth, payload), fields(subject = %payload.subject))]
pub async fn send(
    State(state): State<AppState>,
    _auth: AuthSession,
    payload: ValidatedJson<V1SendNewsletterPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    // Offload to background task
    let subject = payload.subject.clone();
    let text = payload.text.clone();
    let html = payload.html.clone();
    let state_cloned = state.clone();

    tokio::spawn(
        tracing::info_span!("newsletter_send_background", subject = %subject).in_scope(
            || async move {
                // Load confirmed subscribers and send best-effort
                let Ok(subscribers) = SubscriberEntity::find()
                    .filter(SubscriberColumn::Status.eq(SubscriberStatus::Confirmed))
                    .all(&state_cloned.sea_db)
                    .await
                else {
                    error!("Failed to load confirmed subscribers for newsletter send");
                    tracing::Span::current().record("result", "db_error");
                    return;
                };

                let total = subscribers.len();
                info!(count = total, "Sending newsletter to subscribers");

                let mut sent = 0u64;
                let mut failed = 0u64;
                let mut throttled = 0u64;

                for sub in subscribers {
                    let mut attempts = 0u8;
                    loop {
                        match send_mail(
                            &state_cloned.mailer,
                            &sub.email,
                            &subject,
                            html.as_deref(),
                            Some(&text),
                        )
                        .await
                        {
                            Ok(_) => {
                                sent += 1;
                                break;
                            }
                            Err(crate::services::mail::MailError::Throttled {
                                retry_after_secs,
                            }) => {
                                // The shared provider-quota bucket throttled us.
                                // Back off by the limiter's retry window, then
                                // retry this recipient (bounded) rather than
                                // silently dropping it as a generic failure.
                                attempts += 1;
                                if attempts > NEWSLETTER_MAX_THROTTLE_RETRIES {
                                    throttled += 1;
                                    failed += 1;
                                    break;
                                }
                                let wait = retry_after_secs.max(1);
                                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                            }
                            Err(_) => {
                                failed += 1;
                                break;
                            }
                        }
                    }
                    // Pace to stay under the provider per-minute quota so the
                    // next send does not trip the temp block.
                    tokio::time::sleep(NEWSLETTER_PACE).await;
                }

                info!(
                    sent,
                    failed, throttled, total, "Newsletter send task completed"
                );
                tracing::Span::current().record("sent", sent);
                tracing::Span::current().record("failed", failed);
                tracing::Span::current().record("result", "completed");
            },
        ),
    );

    info!("Newsletter send task spawned");

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "message": "Newsletter send queued" })),
    ))
}

#[debug_handler]
#[instrument(skip(state, _auth, payload))]
pub async fn list_subscribers(
    State(state): State<AppState>,
    _auth: AuthSession,
    payload: ValidatedJson<V1ListSubscribersQuery>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let query = payload.0.clone().into_query();

    match SubscriberEntity::find_with_query(&state.sea_db, query).await {
        Ok(result) => {
            info!(
                total = result.total,
                page = payload.page_or_default(),
                "Admin listed newsletter subscribers"
            );
            Ok(Json(json!({
                "data": result.data,
                "total": result.total,
                "per_page": SubscriberEntity::PER_PAGE,
                "page": payload.page_or_default()
            })))
        }
        Err(err) => {
            error!("Failed to list newsletter subscribers: {}", err);
            Err(err)
        }
    }
}

#[debug_handler]
#[instrument(skip(state, payload), fields(email = %payload.email))]
pub async fn confirm(
    State(state): State<AppState>,
    payload: ValidatedJson<V1UnsubscribePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let email = payload.email.trim().to_lowercase();
    let token = payload.token.trim().to_string();

    match SubscriberEntity::confirm(&state.sea_db, &email, &token).await {
        Ok(Some(_)) => {
            info!(email = %email, "Newsletter subscription confirmed");
            Ok(Json(json!({ "message": "Subscription confirmed" })))
        }
        Ok(None) => {
            warn!(email = %email, "Invalid confirmation token");
            Err(ErrorResponse::new(ErrorCode::SubscriberNotFound)
                .with_message("Invalid token or subscriber not found"))
        }
        Err(err) => {
            error!(email = %email, "Failed to confirm subscription: {}", err);
            Err(err)
        }
    }
}
