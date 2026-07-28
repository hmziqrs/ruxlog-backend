use std::collections::HashMap;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_macros::debug_handler;
use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use serde_json::json;
use tracing::{error, info, instrument, warn};

use crate::{
    db::sea_models::{email_verification, user},
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    services::{
        abuse_limiter,
        auth::AuthSession,
        mail::{mail_error_to_response, send_email_verification_code},
    },
    AppState,
};

use super::validator::{
    V1AdminEmailVerificationListPayload, V1AdminEmailVerificationUserPayload, V1VerifyPayload,
};

// Mirror of the private `ADMIN_PER_PAGE` in
// `db/sea_models/email_verification/actions.rs` (the canonical page size for
// `Entity::admin_query`). Kept here so the list response can echo the page size
// without the entity needing to expose its private const.
const ADMIN_PER_PAGE: u64 = 20;

const ABUSE_LIMITER_CONFIG: abuse_limiter::AbuseLimiterConfig = abuse_limiter::AbuseLimiterConfig {
    temp_block_attempts: 3,
    temp_block_range: 360,
    temp_block_duration: 3600,
    block_retry_limit: 5,
    block_range: 900,
    block_duration: 86400,
};

#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id = auth.user.as_ref().map(|u| u.id), code = %payload.code))]
pub async fn verify(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1VerifyPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let user_id = user.id;

    // Throttle code-guessing per account. Fail-closed: a Redis outage denies
    // the attempt rather than allowing unbounded tries.
    let key_prefix = format!("email_verify:{}", user_id);
    abuse_limiter::limiter(&state.redis_pool, &key_prefix, ABUSE_LIMITER_CONFIG).await?;

    let code = payload.0.code;
    let code_hash = crate::utils::code_hash::hash_code(&state.secret_key, &code);

    let verification_result = email_verification::Entity::find_by_user_id_or_code(
        &state.sea_db,
        Some(user_id),
        Some(code_hash),
    )
    .await;

    match verification_result {
        Ok(verification) => {
            if verification.is_expired() {
                warn!(user_id, "Email verification code expired");
                return Err(ErrorResponse::new(ErrorCode::InvalidInput)
                    .with_message("The verification code has expired"));
            }
        }
        Err(err) => {
            warn!(user_id, "Invalid email verification code");
            return Err(err);
        }
    }

    match user::Entity::verify(&state.sea_db, user_id).await {
        Ok(_) => {
            // Single-use: delete the verification row so the (hash of the)
            // code cannot be replayed. Audit: "codes not consumed at verify"
            // — fixed in Phase 3d.
            if let Err(err) = email_verification::Entity::consume(&state.sea_db, user_id).await {
                warn!(user_id, "Failed to consume verification code: {}", err);
            }
            info!(user_id, "Email verified successfully");
            Ok((
                StatusCode::OK,
                Json(json!({
                    "message": "Email verified successfully",
                })),
            ))
        }
        Err(err) => {
            error!(
                user_id,
                "Failed to update user verification status: {}", err
            );
            Err(ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to update user verification status")
                .with_details(err.to_string()))
        }
    }
}

#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn resend(
    state: State<AppState>,
    auth: AuthSession,
) -> Result<impl IntoResponse, ErrorResponse> {
    let pool = &state.sea_db;
    let user = auth.user.unwrap();
    let user_id = user.id;

    match email_verification::Entity::find_by_user_id_or_code(pool, Some(user_id), None).await {
        Ok(verification) => {
            if verification.is_in_delay() {
                warn!(user_id, "Email verification resend in delay period");
                return Err(ErrorResponse::new(ErrorCode::TooManyAttempts).with_message(
                    "Please wait 1 minute before requesting a new verification code",
                ));
            }
        }
        Err(err) => {
            if err.code != ErrorCode::InvalidInput {
                error!(user_id, "Error checking verification delay: {}", err);
                return Err(err);
            }
        }
    }

    // Rate limiting via abuse limiter (3 attempts per 6 minutes)
    let key_prefix = format!("email_verification:{}", user_id);
    match abuse_limiter::limiter(&state.redis_pool, &key_prefix, ABUSE_LIMITER_CONFIG).await {
        Ok(_) => (),
        Err(err) => {
            warn!(user_id, "Abuse limiter blocked verification resend");
            return Err(err);
        }
    }

    // Generate a fresh plaintext code, store only its keyed hash, and email the
    // plaintext. The plaintext never touches the database (audit: "brute-forceable
    // plaintext verification codes" — fixed in Phase 3d).
    let code = email_verification::Entity::generate_code();
    let code_hash = crate::utils::code_hash::hash_code(&state.secret_key, &code);
    email_verification::Entity::regenerate(pool, user_id, code_hash).await?;
    if let Err(err) = send_email_verification_code(&state.mailer, &user.email, &code).await {
        error!(user_id, "Failed to send verification email: {}", err);
        return Err(mail_error_to_response(&err));
    }

    info!(user_id, "Verification email sent");
    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Verification email sent",
        })),
    ))
}

/// Admin-facing view of one email-verification row. The raw `code_hash` (an
/// HMAC) is intentionally NOT exposed — only a `has_code` boolean. Expiry is
/// derived from `updated_at + EXPIRY_TIME` (the same anchor `is_expired` uses).
/// A row's presence means the code is still outstanding: consumption deletes the
/// row (see `Entity::consume`), so there is no separate "consumed" flag.
#[derive(Debug, Serialize)]
struct AdminEmailVerificationRecord {
    id: i32,
    user_id: i32,
    user_email: Option<String>,
    has_code: bool,
    created_at: DateTimeWithTimeZone,
    /// When the current code was issued (`updated_at`); also the expiry anchor.
    issued_at: DateTimeWithTimeZone,
    /// `issued_at + Entity::EXPIRY_TIME` (3h). Precomputed for the client.
    expires_at: DateTimeWithTimeZone,
    is_expired: bool,
    /// True inside the 1-minute resend delay window after `issued_at`.
    is_in_delay: bool,
}

/// `POST /admin/list` — paginated list of outstanding email-verification
/// records, newest first. Behind `ROLE_ADMIN`. Wires the previously-dead
/// `Entity::admin_query` / `AdminEmailVerificationQuery`.
#[debug_handler]
#[instrument(skip(state, _auth, payload))]
pub async fn admin_list(
    state: State<AppState>,
    _auth: AuthSession,
    payload: ValidatedJson<V1AdminEmailVerificationListPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let page = payload.page_no.unwrap_or(1).max(1) as u64;
    let query = payload.0.into_query();

    let (records, total) = email_verification::Entity::admin_query(&state.sea_db, &query).await?;

    // Batch-fetch the owning users so the admin can see who each record belongs
    // to without an N+1. The table is unique on user_id, so this is at most
    // ADMIN_PER_PAGE (20) rows.
    let user_ids: Vec<i32> = records.iter().map(|r| r.user_id).collect();
    let mut emails: HashMap<i32, String> = HashMap::new();
    if !user_ids.is_empty() {
        let users = user::Entity::find()
            .filter(user::Column::Id.is_in(user_ids))
            .all(&state.sea_db)
            .await?;
        for u in users {
            emails.insert(u.id, u.email);
        }
    }

    let expiry = email_verification::Entity::EXPIRY_TIME;
    let data: Vec<AdminEmailVerificationRecord> = records
        .into_iter()
        .map(|m| AdminEmailVerificationRecord {
            user_email: emails.get(&m.user_id).cloned(),
            has_code: !m.code_hash.is_empty(),
            issued_at: m.updated_at,
            expires_at: m.updated_at + expiry,
            is_expired: m.is_expired(),
            is_in_delay: m.is_in_delay(),
            id: m.id,
            user_id: m.user_id,
            created_at: m.created_at,
        })
        .collect();

    info!(total, page, "Admin listed email-verification records");
    Ok((
        StatusCode::OK,
        Json(json!({
            "data": data,
            "total": total,
            "per_page": ADMIN_PER_PAGE,
            "page": page,
        })),
    ))
}

/// `POST /admin/delete` — delete (invalidate) the outstanding verification
/// record for a user. Behind `ROLE_ADMIN`. Reuses `Entity::consume` (the same
/// delete-by-user_id path the verify flow uses to make a code single-use), so
/// there is a single code path for "remove this user's verification row".
#[debug_handler]
#[instrument(skip(state, _auth, payload), fields(target_user_id = payload.user_id))]
pub async fn admin_delete(
    state: State<AppState>,
    _auth: AuthSession,
    payload: ValidatedJson<V1AdminEmailVerificationUserPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user_id = payload.0.user_id;

    match email_verification::Entity::consume(&state.sea_db, user_id).await {
        Ok(0) => {
            warn!(
                user_id,
                "Admin tried to delete non-existent verification record"
            );
            Err(ErrorResponse::new(ErrorCode::RecordNotFound)
                .with_message("No verification record exists for this user"))
        }
        Ok(rows) => {
            info!(user_id, rows, "Admin deleted email-verification record");
            Ok((
                StatusCode::OK,
                Json(json!({ "message": "Verification record deleted" })),
            ))
        }
        Err(err) => {
            error!(
                user_id,
                "Admin failed to delete verification record: {}", err
            );
            Err(err)
        }
    }
}

/// `POST /admin/issue_code` — admin force-issues (rotates) the verification
/// code for a user. This is the domain-meaningful "create/update" for this
/// resource: the only mutable state on a verification row is the code itself
/// (and its `updated_at` expiry anchor), so create and update both collapse to
/// "issue a fresh code". Generates a plaintext code, stores only its keyed hash
/// via `Entity::regenerate`, and emails the plaintext to the user. The plaintext
/// is never returned to the caller. Useful for support cases where a user
/// cannot receive the normal OTP/resend flow.
#[debug_handler]
#[instrument(skip(state, _auth, payload), fields(target_user_id = payload.user_id))]
pub async fn admin_issue_code(
    state: State<AppState>,
    _auth: AuthSession,
    payload: ValidatedJson<V1AdminEmailVerificationUserPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user_id = payload.0.user_id;

    // Confirm the target exists; otherwise we would silently insert an orphan
    // row and attempt to mail a nonexistent address.
    let target = user::Entity::get_by_id(&state.sea_db, user_id)
        .await?
        .ok_or_else(|| {
            ErrorResponse::new(ErrorCode::RecordNotFound)
                .with_message("No user with this ID exists")
        })?;

    let code = email_verification::Entity::generate_code();
    let code_hash = crate::utils::code_hash::hash_code(&state.secret_key, &code);
    email_verification::Entity::regenerate(&state.sea_db, user_id, code_hash).await?;

    if let Err(err) = send_email_verification_code(&state.mailer, &target.email, &code).await {
        error!(user_id, "Failed to send verification email: {}", err);
        return Err(mail_error_to_response(&err));
    }

    info!(user_id, "Admin issued a new email-verification code");
    Ok((
        StatusCode::OK,
        Json(json!({ "message": "Verification code issued and emailed" })),
    ))
}
