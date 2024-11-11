use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::Deserialize;

use crate::{auth::AuthSession, AppState};

#[derive(Deserialize)]
struct MessageQuery {
    phrases: String,
}

pub fn notify_routes() -> Router<AppState> {
    Router::new().route("/", post(notify))
}
async fn notify(
    auth_session: AuthSession,
    state: State<AppState>,
    query: Query<MessageQuery>,
) -> impl IntoResponse {
    let Some(user) = auth_session.user else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let phrases = &query.phrases;
    let content = String::from(format!(
        "Pinging you because at least one of your configured phrases has appeared:\n ### {}",
        phrases
    ));
    println!("Sending message to user: {:?}", user);
    println!("Message content: {}", content);
    state
        .client
        .send_msg(user.discord_id, content)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    Ok(StatusCode::OK.into_response())
}
