use axum::{
    body::{Body, Bytes},
    extract::{BodyStream, Path, State},
    http::{Request, Uri},
    response::IntoResponse,
    routing::{get, post},
    BoxError, Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::{env, io::Error, os::unix::prelude::MetadataExt};
use tokio_util::io::StreamReader;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use axum::body::boxed;
use axum_login::RequireAuthorizationLayer;
use chrono::{DateTime, Utc};
use futures::{Stream, TryStreamExt};
use reqwest::StatusCode;
use tokio::{
    fs::{metadata, read_dir, File},
    io::{self, BufWriter},
};

use crate::{AppState, User};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserInfo {
    name: String,
    email: String,
    discord_avatar: String,
    is_owner: bool,
}
pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/me", get(user_info_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
}
async fn user_info_handler(Extension(user): Extension<User>) -> impl IntoResponse {
    let is_owner = &user.email == &env::var("OWNER_EMAIL").expect("missing OWNER_EMAIL");
    Json(UserInfo {
        name: user.name,
        email: user.email,
        discord_avatar: format!(
            "https://cdn.discordapp.com/avatars/{}/{}",
            user.discord_id.unwrap_or_default(),
            user.avatar_url.unwrap_or_default()
        ),
        is_owner,
    })
}
