//! Error-layer integration for `serde_json::Error` (issue #6).
//!
//! Previously a `serde_json::Error` had no conversion into [`ErrorResponse`], so
//! call sites that produced one either discarded it (e.g. `map_err(|_| ...)`) or
//! fell back to a generic 500. This module classifies a `serde_json::Error` so it
//! can flow through the error layer like any other error type:
//!
//! * Errors that occur *during deserialization* (syntax errors, unexpected EOF,
//!   or any error carrying a source position via [`serde_json::Error::column`])
//!   indicate malformed input from the client and map to
//!   [`ErrorCode::InvalidFormat`] (400).
//! * Everything else (an I/O failure while reading/writing the JSON stream, which
//!   carries no input position) is a server-side fault and maps to
//!   [`ErrorCode::InternalServerError`] (500).
//!
//! With this in place, any handler returning a [`crate::error::DbResult`] can
//! propagate a serde error directly with `?`:
//!
//! ```ignore
//! let value: MyStruct = serde_json::from_str(&raw)?; // -> ErrorResponse (400/500)
//! ```

use crate::error::{ErrorCode, ErrorResponse, IntoErrorResponse};

/// Classify a `serde_json::Error` into the standard error layer.
///
/// Syntax / EOF / positioned errors come from DESERIALIZING client-supplied data
/// and are reported to the caller as a 400 `InvalidFormat`; positional errors are
/// detected via [`serde_json::Error::column`], which is non-zero only for errors
/// raised while parsing a specific input location. Errors with no position
/// (I/O failures on the underlying reader/writer) are treated as server faults
/// (500).
impl IntoErrorResponse for serde_json::Error {
    fn into_error_response(self) -> ErrorResponse {
        // `column()` is non-zero only for errors raised at a specific position in
        // the input, i.e. during deserialization. `is_syntax()` / `is_eof()`
        // additionally flag the common malformed-JSON cases. Together these mean
        // "bad input from the caller" -> 400. Anything else (e.g. an I/O failure
        // on the stream, which has no input position) is a server fault -> 500.
        if self.is_syntax() || self.is_eof() || self.column() != 0 {
            ErrorResponse::new(ErrorCode::InvalidFormat)
                .with_message("JSON deserialization error")
                .with_details(self.to_string())
        } else {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("JSON serialization error")
                .with_details(self.to_string())
        }
    }
}

/// Convenience `From` impl so `serde_json::Error` can be used with `?` in any
/// function returning [`ErrorResponse`] (or [`crate::error::DbResult`]).
impl From<serde_json::Error> for ErrorResponse {
    fn from(err: serde_json::Error) -> Self {
        err.into_error_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialization_syntax_error_maps_to_invalid_format_400() {
        // Malformed JSON -> Category::Syntax (is_syntax() true) -> client 400.
        let err: serde_json::Error = serde_json::from_str::<serde_json::Value>("{ bad }")
            .expect_err("malformed JSON must fail to parse");
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code, ErrorCode::InvalidFormat);
        assert_eq!(resp.status, 400u16);
    }

    #[test]
    fn eof_during_parse_maps_to_invalid_format_400() {
        // Truncated JSON -> Category::Eof (is_eof() true) -> client 400.
        let err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{").expect_err("truncated JSON must fail");
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code, ErrorCode::InvalidFormat);
        assert_eq!(resp.status, 400u16);
    }

    #[test]
    fn io_failure_maps_to_internal_server_error_500() {
        // An I/O failure on the underlying stream carries no input position
        // (`column() == 0`, not a syntax/EOF error) -> server fault 500.
        use std::io::{self, Write};
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let err = serde_json::to_writer(FailingWriter, &serde_json::json!({"x": 1}))
            .expect_err("failing writer must produce an error");
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code, ErrorCode::InternalServerError);
        assert_eq!(resp.status, 500u16);
    }
}
