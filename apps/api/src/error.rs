use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self { status, code, message }
    }
    pub fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Please sign in to continue")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "You don't have permission to do that")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Resource not found")
    }
    pub fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": {"code": self.code, "message": self.message}}))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &error {
            if db.code().as_deref() == Some("23505") {
                return Self::conflict("A record with that value already exists");
            }
            if db.code().as_deref() == Some("23503") {
                return Self::bad_request("Related record does not exist");
            }
        }
        tracing::error!(error = %error, "database operation failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "An internal error occurred")
    }
}
