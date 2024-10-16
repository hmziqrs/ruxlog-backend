use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::constants::STATIC_CSRF;

// pub async fn csrf_gaurd(req: Request, next: Next) -> Result<Response, impl IntoResponse> {
pub async fn csrf_gaurd(req: Request, next: Next) -> Result<Response, Response> {
    let err_json = Json(
        json!({"error": "invalid request", "message": "requset is from a un verified client" }),
    );
    if let Some(token) = req.headers().get("csrf-token") {
        if let Ok(token_str) = token.to_str() {
            use base64::prelude::*;

            let joined = token_str.to_owned() + "==";
            let parsed_token = BASE64_STANDARD.decode(joined);
            match parsed_token {
                Ok(parsed_token) => {
                    let parsed_token = String::from_utf8(parsed_token);
                    if parsed_token.is_err() {
                        return Err((StatusCode::BAD_REQUEST, err_json).into_response());
                    }
                    if parsed_token.unwrap() != STATIC_CSRF {
                        return Err((StatusCode::BAD_REQUEST, err_json).into_response());
                    }

                    Ok(next.run(req).await)
                }
                Err(_) => {
                    return Err((StatusCode::BAD_REQUEST, err_json).into_response());
                }
            }
        } else {
            Err((StatusCode::BAD_REQUEST, err_json).into_response())
        }
    } else {
        Err((StatusCode::FORBIDDEN, err_json).into_response())
    }
}

pub async fn test(req: Request, next: Next) -> Response {
    next.run(req).await
}