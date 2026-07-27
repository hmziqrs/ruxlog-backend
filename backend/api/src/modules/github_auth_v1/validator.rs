use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct GitHubCallbackQuery {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct GitHubExchangeRequest {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

/// `GET https://api.github.com/user` response. Only the fields we use.
///
/// `email` is the user's PUBLIC email and is frequently `null` (users hide it),
/// so the controller additionally calls `/user/emails` to find the primary
/// verified address. `id` is the stable numeric GitHub subject identifier we
/// link on (stored as a string in the identity table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUserInfo {
    pub id: i64,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

/// One entry from `GET https://api.github.com/user/emails`. GitHub exposes a
/// real per-email `verified` flag — unlike Facebook — so we can apply the
/// email-verified link/create gate precisely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
    #[serde(default)]
    pub visibility: Option<String>,
}
