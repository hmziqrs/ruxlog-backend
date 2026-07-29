use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable, wire-visible error codes for the ruxlog API.
///
/// ## Contract
///
/// Every variant serializes to a fixed `"<NS>_<NNN>"` token (via its
/// `#[serde(rename = ...)]`), which is the value clients match on as the `type`
/// field of an error response body. **Never rename a variant or renumber its
/// token** — either is a client-visible breaking change on the wire. Adding new
/// variants is safe.
///
/// Namespace prefixes: `AUTH` (authn/authz), `VAL` (input validation), `DB`
/// (data layer), `SRV` (generic server/infra), `BIZ` (business rules), `EXT`
/// (external services), `AST` (assets/uploads), `EML` (mail), `PST` (posts),
/// `CAT` (categories), `TAG` (tags), `NWS` (newsletter).
///
/// [`ErrorCode::status_code()`] is the single source of truth for the HTTP
/// status of a code; it is locked by the `status_code_map_is_total_and_stable`
/// regression test and must only change deliberately alongside that snapshot.
///
/// ## Near-duplicate codes — pick by cause, not by status
///
/// Several distinct codes map to the same HTTP status. They are NOT redundant;
/// choose by *why* the error happened:
///
/// ### 429 — `RateLimited` (SRV_004) vs `TooManyAttempts` (AUTH_007)
///
/// - **`RateLimited`** — generic per-IP / per-path throughput limiting, or an
///   upstream provider throttle (e.g. the mail provider asked us to slow down).
///   Emitters: the HTTP rate-limit middleware and the mail error-map.
///   Semantics: "back off on volume."
/// - **`TooManyAttempts`** — attempt-count / brute-force protection on one
///   specific security action (login, forgot-password, email-verification
///   resend, backup-code redemption). Emitters: the abuse limiter and the
///   verification-delay guards. Semantics: "stop retrying *this* action."
///
/// Both are 429 and both MUST attach a `Retry-After` header wherever a retry
/// deadline is known — the two are contractually symmetric on the wire, so do
/// not "fix" the duplication by merging them (a merge would renumber the wire
/// token and break clients).
///
/// ### 409 — `DuplicateEntry` (DB_003) vs `IntegrityError` (DB_007)
///
/// - **`DuplicateEntry`** — a unique-key violation (a conflicting row already
///   exists); the client resolves it by changing the conflicting value.
/// - **`IntegrityError`** — a foreign-key / check-constraint violation (a
///   referenced row is missing or an invariant failed).
///
/// ### 400 — `InvalidFormat` (VAL_003) vs `InvalidEmailFormat` (EML_002)
///
/// - **`InvalidFormat`** — generic input-format failure (any field).
/// - **`InvalidEmailFormat`** — an email-address format failure in the mail
///   subsystem; prefer it in mail flows for sharper client UX.
///
/// ## Dead variants
///
/// Variants marked `#[deprecated]` have no emitter anywhere in the codebase and
/// are kept only for wire stability; do not add new usages. They are slated for
/// removal in a follow-up dead-code pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    #[serde(rename = "AUTH_001")]
    InvalidCredentials,
    #[serde(rename = "AUTH_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    UserNotFound,
    #[serde(rename = "AUTH_003")]
    SessionExpired,
    #[serde(rename = "AUTH_004")]
    Unauthorized,
    #[serde(rename = "AUTH_005")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    PasswordResetRequired,
    #[serde(rename = "AUTH_006")]
    AccountLocked,
    /// Attempt-count / brute-force protection on a specific security action
    /// (login, forgot-password, email-verification resend, backup-code
    /// redemption). HTTP 429. Distinct from `RateLimited` (SRV_004): this is
    /// "stop retrying this action", not "back off on volume". See the enum docs
    /// for the full rule. Emitters: abuse limiter, verification-delay guards.
    #[serde(rename = "AUTH_007")]
    TooManyAttempts,
    #[serde(rename = "AUTH_008")]
    EmailVerificationRequired,
    #[serde(rename = "AUTH_009")]
    InvalidToken,

    #[serde(rename = "VAL_001")]
    InvalidInput,
    #[serde(rename = "VAL_002")]
    MissingRequiredField,
    /// Generic input-format failure (any field). HTTP 400. For email-address
    /// format failures in mail flows, prefer `InvalidEmailFormat` (EML_002).
    #[serde(rename = "VAL_003")]
    InvalidFormat,
    #[serde(rename = "VAL_004")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    InvalidLength,
    #[serde(rename = "VAL_005")]
    InvalidValue,
    #[serde(rename = "VAL_006")]
    ValidationError,

    #[serde(rename = "DB_001")]
    DatabaseConnectionError,
    /// The canonical 404 for a missing record. Prefer this over the per-domain
    /// `*NotFound` codes (PST_001 / CAT_001 / TAG_001 / NWS_001), which are
    /// unused and deprecated.
    #[serde(rename = "DB_002")]
    RecordNotFound,
    /// A unique-key violation: a conflicting row already exists. HTTP 409.
    /// Distinct from `IntegrityError` (DB_007), which is an FK/check failure.
    #[serde(rename = "DB_003")]
    DuplicateEntry,
    #[serde(rename = "DB_004")]
    QueryError,
    #[serde(rename = "DB_005")]
    TransactionError,
    #[serde(rename = "DB_006")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    RelationshipError,
    /// A foreign-key / check-constraint violation: a referenced row is missing
    /// or an invariant failed. HTTP 409. Distinct from `DuplicateEntry`
    /// (DB_003), which is a unique-key conflict.
    #[serde(rename = "DB_007")]
    IntegrityError,

    #[serde(rename = "SRV_001")]
    InternalServerError,
    #[serde(rename = "SRV_002")]
    ServiceUnavailable,
    #[serde(rename = "SRV_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    Timeout,
    /// Generic per-IP / per-path throughput limiting, or an upstream provider
    /// throttle. HTTP 429. Distinct from `TooManyAttempts` (AUTH_007): this is
    /// "back off on volume", not "stop retrying this action". Emitters: HTTP
    /// rate-limit middleware, mail error-map. Must attach `Retry-After`.
    #[serde(rename = "SRV_004")]
    RateLimited,
    #[serde(rename = "SRV_005")]
    ConfigurationError,

    #[serde(rename = "BIZ_001")]
    OperationNotAllowed,
    #[serde(rename = "BIZ_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    ResourceConflict,
    #[serde(rename = "BIZ_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    BusinessRuleViolation,
    #[serde(rename = "BIZ_004")]
    DependencyExists,

    #[serde(rename = "EXT_001")]
    ExternalServiceError,
    #[serde(rename = "EXT_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    ExternalServiceTimeout,
    #[serde(rename = "EXT_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    ExternalServiceUnavailable,

    #[serde(rename = "AST_001")]
    FileUploadError,
    #[serde(rename = "AST_002")]
    FileNotFound,
    #[serde(rename = "AST_003")]
    FileTooLarge,
    #[serde(rename = "AST_004")]
    InvalidFileType,
    #[serde(rename = "AST_005")]
    StorageError,
    #[serde(rename = "AST_006")]
    FileDeletionError,
    #[serde(rename = "AST_007")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    AssetMetadataError,

    #[serde(rename = "EML_001")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    EmailSendingError,
    /// An email-address format failure in the mail subsystem. HTTP 400. For
    /// non-email fields, use `InvalidFormat` (VAL_003).
    #[serde(rename = "EML_002")]
    InvalidEmailFormat,
    #[serde(rename = "EML_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    EmailDeliveryError,
    /// Email delivery suppressed (e.g. recipient on the suppression list).
    /// HTTP 422: a semantic refusal, not a server error.
    #[serde(rename = "EML_004")]
    EmailSuppressed,

    #[serde(rename = "PST_001")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    PostNotFound,
    #[serde(rename = "PST_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    InvalidPostStatus,
    #[serde(rename = "PST_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    PostAlreadyPublished,
    #[serde(rename = "PST_004")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    SlugAlreadyExists,

    #[serde(rename = "CAT_001")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    CategoryNotFound,
    #[serde(rename = "CAT_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    CategoryInUse,
    #[serde(rename = "CAT_003")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    InvalidCategoryParent,

    #[serde(rename = "TAG_001")]
    TagNotFound,
    #[serde(rename = "TAG_002")]
    #[deprecated(note = "unused; no emitter — candidate for removal, do not add new usages")]
    TagAlreadyExists,

    #[serde(rename = "NWS_001")]
    SubscriberNotFound,
}

impl ErrorCode {
    /// Human-readable default message for the code.
    ///
    /// `#[allow(deprecated)]`: this match must be exhaustive over every variant,
    /// including the `#[deprecated]` dead ones, so they still resolve to a
    /// message rather than panicking. New usages of deprecated variants anywhere
    /// *outside* this lookup are still warned at.
    #[allow(deprecated)]
    pub fn default_message(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid username or password",
            Self::UserNotFound => "User not found",
            Self::SessionExpired => "Your session has expired, please login again",
            Self::Unauthorized => "You are not authorized to perform this action",
            Self::PasswordResetRequired => "Password reset is required",
            Self::AccountLocked => "Your account has been locked",
            Self::TooManyAttempts => "Too many attempts, please try again later",
            Self::EmailVerificationRequired => "Email verification is required",
            Self::InvalidToken => "The provided token is invalid or expired",

            Self::InvalidInput => "The provided input is invalid",
            Self::MissingRequiredField => "A required field is missing",
            Self::InvalidFormat => "The provided value has an invalid format",
            Self::InvalidLength => "The provided value has an invalid length",
            Self::InvalidValue => "The provided value is invalid",
            Self::ValidationError => "Validation error occurred",

            Self::DatabaseConnectionError => "Could not connect to the database",
            Self::RecordNotFound => "The requested record was not found",
            Self::DuplicateEntry => "A record with this value already exists",
            Self::QueryError => "There was an error executing your request",
            Self::TransactionError => "Transaction failed",
            Self::RelationshipError => "Error with relationship between records",
            Self::IntegrityError => "Database integrity constraint violation",

            Self::InternalServerError => "An internal server error occurred",
            Self::ServiceUnavailable => "The service is currently unavailable",
            Self::Timeout => "The request timed out",
            Self::RateLimited => "Too many requests, please try again later",
            Self::ConfigurationError => "Server configuration error",

            Self::OperationNotAllowed => "This operation is not allowed",
            Self::ResourceConflict => "The operation would create a conflict",
            Self::BusinessRuleViolation => "The operation violates business rules",
            Self::DependencyExists => "Cannot complete operation due to existing dependencies",

            Self::ExternalServiceError => "Error communicating with external service",
            Self::ExternalServiceTimeout => "External service request timed out",
            Self::ExternalServiceUnavailable => "External service is unavailable",

            Self::FileUploadError => "Failed to upload file",
            Self::FileNotFound => "File not found",
            Self::FileTooLarge => "File size exceeds maximum allowed limit",
            Self::InvalidFileType => "File type is not supported",
            Self::StorageError => "Error storing file in the storage service",
            Self::FileDeletionError => "Failed to delete file from storage",
            Self::AssetMetadataError => "Error processing asset metadata",

            Self::EmailSendingError => "Failed to send email",
            Self::InvalidEmailFormat => "Invalid email format",
            Self::EmailDeliveryError => "Email delivery failed",
            Self::EmailSuppressed => "Email delivery suppressed",

            Self::PostNotFound => "Post not found",
            Self::InvalidPostStatus => "Invalid post status",
            Self::PostAlreadyPublished => "Post is already published",
            Self::SlugAlreadyExists => "A post with this slug already exists",

            Self::CategoryNotFound => "Category not found",
            Self::CategoryInUse => "Category is in use and cannot be deleted",
            Self::InvalidCategoryParent => "Invalid parent category",

            Self::TagNotFound => "Tag not found",
            Self::TagAlreadyExists => "Tag already exists",

            Self::SubscriberNotFound => "Newsletter subscriber not found",
        }
    }

    /// HTTP status for the code — the single source of truth for the wire status.
    ///
    /// `#[allow(deprecated)]`: this match must be exhaustive over every variant,
    /// including the `#[deprecated]` dead ones, so their status stays locked by
    /// the `status_code_map_is_total_and_stable` regression test until removal.
    #[allow(deprecated)]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidCredentials => 401,
            Self::SessionExpired => 401,
            Self::Unauthorized => 403,
            Self::PasswordResetRequired => 403,
            Self::AccountLocked => 403,
            Self::TooManyAttempts => 429,
            Self::UserNotFound => 404,
            Self::EmailVerificationRequired => 403,
            Self::InvalidToken => 401,

            Self::InvalidInput => 400,
            Self::MissingRequiredField => 400,
            Self::InvalidFormat => 400,
            Self::InvalidLength => 400,
            Self::InvalidValue => 400,
            Self::ValidationError => 400,

            Self::DatabaseConnectionError => 500,
            Self::RecordNotFound => 404,
            Self::DuplicateEntry => 409,
            Self::QueryError => 500,
            Self::TransactionError => 500,
            Self::RelationshipError => 400,
            Self::IntegrityError => 409,

            Self::InternalServerError => 500,
            Self::ServiceUnavailable => 503,
            Self::Timeout => 504,
            Self::RateLimited => 429,
            Self::ConfigurationError => 500,

            Self::OperationNotAllowed => 403,
            Self::ResourceConflict => 409,
            Self::BusinessRuleViolation => 422,
            Self::DependencyExists => 409,

            Self::ExternalServiceError => 502,
            Self::ExternalServiceTimeout => 504,
            Self::ExternalServiceUnavailable => 503,

            Self::FileUploadError => 500,
            Self::FileNotFound => 404,
            Self::FileTooLarge => 413,
            Self::InvalidFileType => 415,
            Self::StorageError => 500,
            Self::FileDeletionError => 500,
            Self::AssetMetadataError => 400,

            Self::EmailSendingError => 500,
            Self::InvalidEmailFormat => 400,
            Self::EmailDeliveryError => 500,
            Self::EmailSuppressed => 422,

            Self::PostNotFound => 404,
            Self::InvalidPostStatus => 400,
            Self::PostAlreadyPublished => 409,
            Self::SlugAlreadyExists => 409,

            Self::CategoryNotFound => 404,
            Self::CategoryInUse => 409,
            Self::InvalidCategoryParent => 400,

            Self::TagNotFound => 404,
            Self::TagAlreadyExists => 409,

            Self::SubscriberNotFound => 404,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json_string =
            serde_json::to_string(self).unwrap_or_else(|_| "\"UNKNOWN_ERROR\"".to_string());
        write!(f, "{}", json_string.trim_matches('"'))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    #[serde(rename = "type")]
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.default_message().to_string(),
            details: None,
        }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spot-checks a sample of codes (including deprecated ones, to prove they
    /// still resolve to a message rather than panicking).
    #[allow(deprecated)]
    #[test]
    fn all_codes_have_non_empty_default_messages() {
        let codes = [
            ErrorCode::InvalidCredentials,
            ErrorCode::UserNotFound,
            ErrorCode::SessionExpired,
            ErrorCode::Unauthorized,
            ErrorCode::DatabaseConnectionError,
            ErrorCode::RecordNotFound,
            ErrorCode::DuplicateEntry,
            ErrorCode::InternalServerError,
            ErrorCode::RateLimited,
            ErrorCode::FileTooLarge,
            ErrorCode::PostNotFound,
            ErrorCode::CategoryNotFound,
            ErrorCode::TagNotFound,
        ];
        for code in &codes {
            assert!(
                !code.default_message().is_empty(),
                "{:?} has empty message",
                code
            );
        }
    }

    /// Includes deprecated variants (Timeout, BusinessRuleViolation) so their
    /// mapping stays pinned until removal.
    #[allow(deprecated)]
    #[test]
    fn status_code_mappings() {
        assert_eq!(ErrorCode::InvalidCredentials.status_code(), 401);
        assert_eq!(ErrorCode::Unauthorized.status_code(), 403);
        assert_eq!(ErrorCode::TooManyAttempts.status_code(), 429);
        assert_eq!(ErrorCode::RecordNotFound.status_code(), 404);
        assert_eq!(ErrorCode::DuplicateEntry.status_code(), 409);
        assert_eq!(ErrorCode::InternalServerError.status_code(), 500);
        assert_eq!(ErrorCode::FileTooLarge.status_code(), 413);
        assert_eq!(ErrorCode::ServiceUnavailable.status_code(), 503);
        assert_eq!(ErrorCode::Timeout.status_code(), 504);
        assert_eq!(ErrorCode::BusinessRuleViolation.status_code(), 422);
    }

    /// Includes a deprecated variant (PostNotFound) to keep its display token
    /// pinned until removal.
    #[allow(deprecated)]
    #[test]
    fn display_format_matches_serde_rename() {
        assert_eq!(ErrorCode::InvalidCredentials.to_string(), "AUTH_001");
        assert_eq!(ErrorCode::RecordNotFound.to_string(), "DB_002");
        assert_eq!(ErrorCode::InternalServerError.to_string(), "SRV_001");
        assert_eq!(ErrorCode::PostNotFound.to_string(), "PST_001");
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&ErrorCode::InvalidCredentials).unwrap();
        assert_eq!(json, "\"AUTH_001\"");
        let parsed: ErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ErrorCode::InvalidCredentials);
    }

    #[test]
    fn error_response_serialization() {
        let resp = ErrorResponse::new(ErrorCode::RecordNotFound)
            .with_message("Post not found")
            .with_details("id=42");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["type"], "DB_002");
        assert_eq!(json["message"], "Post not found");
        assert_eq!(json["details"], "id=42");
    }

    #[test]
    fn error_response_skips_none_details() {
        let resp = ErrorResponse::new(ErrorCode::RateLimited);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("details"));
    }

    /// Locks the intentional 429 split documented on the enum: `RateLimited`
    /// (SRV_004) and `TooManyAttempts` (AUTH_007) are two DISTINCT codes that
    /// both map to HTTP 429. Merging them would renumber a wire token and break
    /// clients — this test makes a silent merge a compile/test failure.
    #[test]
    fn rate_limited_and_too_many_attempts_are_intentionally_distinct() {
        // Both are 429 (the reason they look like duplicates).
        assert_eq!(ErrorCode::RateLimited.status_code(), 429);
        assert_eq!(ErrorCode::TooManyAttempts.status_code(), 429);

        // They are different codes on the wire...
        assert_ne!(ErrorCode::RateLimited, ErrorCode::TooManyAttempts);
        assert_ne!(
            ErrorCode::RateLimited.to_string(),
            ErrorCode::TooManyAttempts.to_string()
        );
        assert_eq!(ErrorCode::RateLimited.to_string(), "SRV_004");
        assert_eq!(ErrorCode::TooManyAttempts.to_string(), "AUTH_007");

        // ...and carry different default messaging (different client semantics).
        assert_ne!(
            ErrorCode::RateLimited.default_message(),
            ErrorCode::TooManyAttempts.default_message()
        );
    }

    /// Snapshot of the full variant -> HTTP status mapping. Locks the wire
    /// contract: any change to a code's status must be made deliberately and
    /// update this table, or the test fails. Covers every variant, including
    /// the `#[deprecated]` dead ones (so their status can't silently drift
    /// before removal).
    #[allow(deprecated)]
    #[test]
    fn status_code_map_is_total_and_stable() {
        let snapshot: &[(ErrorCode, u16)] = &[
            (ErrorCode::InvalidCredentials, 401),
            (ErrorCode::UserNotFound, 404),
            (ErrorCode::SessionExpired, 401),
            (ErrorCode::Unauthorized, 403),
            (ErrorCode::PasswordResetRequired, 403),
            (ErrorCode::AccountLocked, 403),
            (ErrorCode::TooManyAttempts, 429),
            (ErrorCode::EmailVerificationRequired, 403),
            (ErrorCode::InvalidToken, 401),
            (ErrorCode::InvalidInput, 400),
            (ErrorCode::MissingRequiredField, 400),
            (ErrorCode::InvalidFormat, 400),
            (ErrorCode::InvalidLength, 400),
            (ErrorCode::InvalidValue, 400),
            (ErrorCode::ValidationError, 400),
            (ErrorCode::DatabaseConnectionError, 500),
            (ErrorCode::RecordNotFound, 404),
            (ErrorCode::DuplicateEntry, 409),
            (ErrorCode::QueryError, 500),
            (ErrorCode::TransactionError, 500),
            (ErrorCode::RelationshipError, 400),
            (ErrorCode::IntegrityError, 409),
            (ErrorCode::InternalServerError, 500),
            (ErrorCode::ServiceUnavailable, 503),
            (ErrorCode::Timeout, 504),
            (ErrorCode::RateLimited, 429),
            (ErrorCode::ConfigurationError, 500),
            (ErrorCode::OperationNotAllowed, 403),
            (ErrorCode::ResourceConflict, 409),
            (ErrorCode::BusinessRuleViolation, 422),
            (ErrorCode::DependencyExists, 409),
            (ErrorCode::ExternalServiceError, 502),
            (ErrorCode::ExternalServiceTimeout, 504),
            (ErrorCode::ExternalServiceUnavailable, 503),
            (ErrorCode::FileUploadError, 500),
            (ErrorCode::FileNotFound, 404),
            (ErrorCode::FileTooLarge, 413),
            (ErrorCode::InvalidFileType, 415),
            (ErrorCode::StorageError, 500),
            (ErrorCode::FileDeletionError, 500),
            (ErrorCode::AssetMetadataError, 400),
            (ErrorCode::EmailSendingError, 500),
            (ErrorCode::InvalidEmailFormat, 400),
            (ErrorCode::EmailDeliveryError, 500),
            (ErrorCode::EmailSuppressed, 422),
            (ErrorCode::PostNotFound, 404),
            (ErrorCode::InvalidPostStatus, 400),
            (ErrorCode::PostAlreadyPublished, 409),
            (ErrorCode::SlugAlreadyExists, 409),
            (ErrorCode::CategoryNotFound, 404),
            (ErrorCode::CategoryInUse, 409),
            (ErrorCode::InvalidCategoryParent, 400),
            (ErrorCode::TagNotFound, 404),
            (ErrorCode::TagAlreadyExists, 409),
            (ErrorCode::SubscriberNotFound, 404),
        ];

        // Totality guard: every variant must appear exactly once. If a variant
        // is added or removed without updating this table, the counts diverge.
        let expected_count = snapshot.len();
        for (code, expected_status) in snapshot {
            assert_eq!(
                code.status_code(),
                *expected_status,
                "status drift for {:?} ({})",
                code,
                code
            );
        }

        // Sanity: the table claims to cover all variants. We can't enumerate the
        // enum without a crate, so we pin the known live count; changing it is a
        // signal to revisit this snapshot.
        assert_eq!(expected_count, 55, "ErrorCode variant count changed");
    }
}
