use sea_orm::prelude::DateTimeWithTimeZone;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct NewPostView {
    pub post_id: i32,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PostViewQuery {
    pub page_no: Option<u64>,
    pub post_id: i32,
    pub ip_address: Option<String>,
    pub user_id: Option<i32>,
    pub created_at: Option<DateTimeWithTimeZone>,
    pub sort_by: Option<Vec<String>>,
    pub sort_order: Option<String>,
}