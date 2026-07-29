/// Errors returned by the gate primitives.
///
/// Both variants are fail-CLOSED signals: the caller MUST deny the request.
/// (The fail-*open* primitive, [`crate::dedup_nx`], returns a plain `bool` and
/// therefore has no error type to misuse.)
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// Redis/`EVAL` failed. Deny (the store cannot vouch for the count).
    #[error("rate-limit store unavailable: {0}")]
    StoreUnavailable(String),
    /// The Lua script returned an unexpected arity. Deny (defensive).
    #[error("rate-limit store returned an unexpected result")]
    UnexpectedResult,
}
