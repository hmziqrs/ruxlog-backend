use serde::Deserialize;

use ruxlog_types::enums::SuppressionReason;

/// Query params for `GET /mail/v1/suppression`.
#[derive(Debug, Deserialize, Default)]
pub struct V1ListSuppressionsQuery {
    #[serde(default)]
    pub page: Option<u64>,
    pub reason: Option<SuppressionReason>,
    pub permanent: Option<bool>,
    pub search: Option<String>,
}

/// Query param for `DELETE /mail/v1/suppression?recipient=...`.
#[derive(Debug, Deserialize)]
pub struct V1DeleteSuppression {
    pub recipient: String,
}

/// Body for `POST /mail/v1/suppression` (manual blacklist add).
#[derive(Debug, Deserialize)]
pub struct V1CreateSuppression {
    pub recipient: String,
    #[serde(default)]
    pub reason: Option<SuppressionReason>,
    #[serde(default)]
    pub permanent: bool,
    pub diagnostic: Option<String>,
}

impl V1CreateSuppression {
    /// Default a missing reason to `manual`.
    pub fn reason_or_default(&self) -> SuppressionReason {
        self.reason.unwrap_or(SuppressionReason::Manual)
    }
}
