use garde::{self, Validate};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Deserialize, Serialize, Validate)]
#[garde(context(AppState))]
pub struct V1LoginPayload {
    #[garde(email)]
    pub email: String,
    #[garde(length(min = 1))]
    pub password: String,
}
