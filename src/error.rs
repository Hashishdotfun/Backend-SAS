use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("Database error: {0}")]
    Db(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let body = ErrorResponse {
            error: self.to_string(),
        };
        match self {
            ApiError::InvalidRequest(_) => HttpResponse::BadRequest().json(body),
            ApiError::Internal(_) | ApiError::Jwt(_) | ApiError::Db(_) => {
                HttpResponse::InternalServerError().json(body)
            }
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Db(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        ApiError::Jwt(e.to_string())
    }
}
