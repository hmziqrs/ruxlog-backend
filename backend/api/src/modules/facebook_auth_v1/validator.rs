use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct FacebookCallbackQuery {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct FacebookExchangeRequest {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

/// Facebook Graph API `/me?fields=id,name,email` response.
///
/// `email` is optional: a user may deny the email permission. `name` is
/// optional for accounts that never set a display name. `id` is always present
/// and is the stable provider subject identifier we link on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacebookUserInfo {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
}
