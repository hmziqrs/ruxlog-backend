// The canonical error type (`ErrorResponse`) is intentionally >128 B (it carries
// code + message + status + optional details/context/retry_after/request_id for
// rich, structured API errors). clippy::result_large_err flags every function
// returning `Result<T, ErrorResponse>` / `DbResult<T>`, which is essentially the
// whole service + data layer. Suppress crate-wide instead of annotating each fn.
#![allow(clippy::result_large_err)]

pub mod config;
pub mod db;
#[cfg(feature = "openapi")]
pub mod docs;
pub mod error;
pub mod extractors;
pub mod middlewares;
pub mod modules;
pub mod router;
pub mod services;
pub mod state;
pub mod utils;

#[cfg(feature = "seed-system")]
pub mod tui;

#[cfg(test)]
pub mod test_utils;

pub use crate::state::AppState;
