use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post}, Json, Router,
};
use sqlx::{Pool, Sqlite};









use reqwest::StatusCode;


use crate::{AppState, RequireAuth, Role, UserInvite, UPLOADS_DIRECTORY};
pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/bucket/create/:name", post(create_bucket))
        .route(
            "/invites",
            get(get_invites).put(put_invite).delete(delete_invite),
        )
        .route_layer(RequireAuth::login_with_role(Role::Admin..))
}
async fn create_bucket(Path(name): Path<String>) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, name);
    match tokio::fs::create_dir(path).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
    }
}

async fn get_invites(state: State<AppState>) -> impl IntoResponse {
    let pool = &state.pool;
    let invites = sqlx::query_as!(UserInvite, "select * from user_invites order by email ")
        .fetch_all(pool)
        .await
        .unwrap();
    Json(invites)
}
async fn put_invite(state: State<AppState>, Json(invite): Json<UserInvite>) -> impl IntoResponse {
    let pool = &state.pool;
    if invite.email.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Email cannot be an empty string".to_string(),
        ));
    }
    let existing = get_user_invite(pool, &invite.email).await;
    if existing.is_some() {
        return Err((StatusCode::BAD_REQUEST, "Email already exists".to_string()));
    }
    sqlx::query!("insert into user_invites (email) values ($1)", invite.email)
        .execute(pool)
        .await
        .unwrap();
    let invite = get_user_invite(pool, &invite.email).await;
    Ok(Json(invite.unwrap()))
}

async fn delete_invite(
    state: State<AppState>,
    Json(invite): Json<UserInvite>,
) -> impl IntoResponse {
    let pool = &state.pool;
    let existing = get_user_invite(pool, &invite.email).await;
    if existing.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Email doesn't exist".to_string()));
    }
    sqlx::query!("delete from user_invites where email = $1", invite.email)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query!("delete from users where email = $1", invite.email)
        .execute(pool)
        .await
        .unwrap();
    Ok(StatusCode::NO_CONTENT)
}

async fn get_user_invite(pool: &Pool<Sqlite>, email: &String) -> Option<UserInvite> {
    sqlx::query_as!(
        UserInvite,
        "select * from user_invites where email = $1",
        email
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}
