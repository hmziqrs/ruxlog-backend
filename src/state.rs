use deadpool_diesel::postgres::Pool;
use fred::prelude::RedisPool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Pool,
    pub redis_pool: RedisPool,
}