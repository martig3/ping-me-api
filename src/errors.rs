use oauth2::{basic::BasicRequestTokenError, reqwest::AsyncHttpClientError};

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),

    #[error("User email has no invite")]
    NoEmail,
}
