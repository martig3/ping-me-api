use axum::{response::IntoResponse, routing::get, Json, Router};
use serde::{Deserialize, Serialize};

use std::env;

use crate::{auth::AuthSession, AppState};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserInfo {
    name: String,
    email: String,
    discord_avatar: String,
    is_owner: bool,
}
pub fn user_routes() -> Router<AppState> {
    Router::new().route("/me", get(user_info_handler))
}
async fn user_info_handler(auth_session: AuthSession) -> impl IntoResponse {
    let user = auth_session.user.unwrap();
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
