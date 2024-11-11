use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oauth2::{basic::BasicRequestTokenError, reqwest::AsyncHttpClientError};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    SerdeJSON(#[from] serde_json::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),
    #[error("User has no email")]
    NoEmail,
    #[error("Error occurred while authenticating user")]
    GenericError,
}

impl IntoResponse for BackendError {
    fn into_response(self) -> Response {
        let json = json!({
            "error": self.to_string(),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, json.to_string()).into_response()
    }
}
