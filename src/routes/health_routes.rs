use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};

use crate::AppState;

pub fn health_routes() -> Router<AppState> {
    Router::new().route("/", get(health))
}

pub async fn health() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
