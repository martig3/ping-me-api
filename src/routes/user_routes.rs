use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::{Deserialize, Serialize};

use crate::{auth::AuthSession, AppState};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserInfo {
    name: String,
    email: String,
    discord_avatar: String,
}
pub fn user_routes() -> Router<AppState> {
    Router::new().route("/me", get(user_info_handler))
}
async fn user_info_handler(auth_session: AuthSession) -> impl IntoResponse {
    let Some(user) = auth_session.user else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    Ok(Json(UserInfo {
        name: user.name,
        email: user.email,
        discord_avatar: format!(
            "https://cdn.discordapp.com/avatars/{}/{}",
            user.discord_id,
            user.avatar_url.unwrap_or_default()
        ),
    }))
}
