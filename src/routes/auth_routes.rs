use crate::Role;
use crate::UserInvite;


use axum::extract::Query;
use axum::extract::State;

use axum::response::Redirect;
use axum::Extension;
use axum::{
    response::IntoResponse,
    routing::{get}, Router,
};

use axum_login::axum_sessions::extractors::ReadableSession;
use axum_login::axum_sessions::extractors::WritableSession;





use axum_login::RequireAuthorizationLayer;


use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope,
};



use serde::Deserialize;
use serde::Serialize;



use std::env;












use tracing::log;


use crate::AppState;
use crate::AuthContext;
use crate::User;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: CsrfToken,
}
#[derive(Debug, Serialize, Deserialize)]
struct DiscordUser {
    id: String,
    avatar: Option<String>,
    username: String,
    email: Option<String>,
    discriminator: String,
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/logout", get(logout_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
        .route("/login", get(login_handler))
        .route("/discord/callback", get(oauth_callback_handler))
}
async fn logout_handler(mut auth: AuthContext) -> impl IntoResponse {
    log::debug!("Logging out user: {:?}", &auth.current_user);
    auth.logout().await
}
async fn login_handler(
    Extension(client): Extension<BasicClient>,
    mut session: WritableSession,
) -> impl IntoResponse {
    // Generate the authorization URL to which we'll redirect the user.
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .url();

    // Store the csrf_state in the session so we can assert equality in the callback
    session.insert("csrf_state", csrf_state).unwrap();

    // Redirect to your oauth service
    Redirect::to(auth_url.as_ref())
}
async fn oauth_callback_handler(
    mut auth: AuthContext,
    state: State<AppState>,
    Query(query): Query<AuthRequest>,
    Extension(oauth_client): Extension<BasicClient>,
    session: ReadableSession,
) -> impl IntoResponse {
    let pool = &state.pool;
    log::debug!("Running oauth callback {query:?}");
    // Compare the csrf state in the callback with the state generated before the
    // request
    let original_csrf_state: CsrfToken = session.get("csrf_state").unwrap();
    let query_csrf_state = query.state.secret();
    let csrf_state_equal = original_csrf_state.secret() == query_csrf_state;

    drop(session);

    if !csrf_state_equal {
        log::debug!("csrf state is invalid, cannot login",);

        // Return to some error
        return Redirect::to(
            format!(
                "{}/errors/invalid-csrf",
                env::var("CLIENT_BASE_URL").unwrap()
            )
            .as_str(),
        );
    }

    log::debug!("Getting oauth token");
    // Get an auth token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .unwrap();

    // Fetch user data from discord
    let client = reqwest::Client::new();
    let user_data = client
        // https://discord.com/developers/docs/resources/user#get-current-user
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap()
        .json::<DiscordUser>()
        .await
        .unwrap();
    log::debug!("Getting db connection");

    let Some(email) = user_data.email else {
        return Redirect::to("/no-email");
    };

    // Fetch the user and log them in
    let mut conn = pool.acquire().await.unwrap();
    log::debug!("Getting user");
    let user: Option<User> = sqlx::query_as!(User, r#"select u.id, u.name, u.email, u.password_hash, u.role as "role: Role", u.avatar_url, u.discord_id from users as u where email = $1"#, email)
        .fetch_optional(&mut conn)
        .await
        .unwrap();
    let user = match user {
        Some(user) => user,
        None => {
            let is_owner = &email == &env::var("OWNER_EMAIL").expect("Missing OWNER_EMAIL");
            if !is_owner {
                let Some(_invite) = sqlx::query_as!( UserInvite, "select * from user_invites where email = $1",
                    email
                )
                .fetch_optional(&mut conn)
                .await
                .unwrap() else {
                    return Redirect::to(format!("{}/no-invite", env::var("CLIENT_BASE_URL").unwrap()).as_str());
                };
            }

            let role = if is_owner { Role::Admin } else { Role::User };
            sqlx::query!(
                "insert into users (password_hash, name, email, role, avatar_url, discord_id) values ($1, $2, $3, $4, $5, $6);",
                user_data.username,
                user_data.username,
                email,
                role,
                user_data.avatar,
                user_data.id,
            )
            .execute(&mut conn)
            .await
            .unwrap();
            let user: User = sqlx::query_as!(
                User,
                r#"select u.id, u.name, u.email, u.password_hash, u.role as "role: Role", u.avatar_url, u.discord_id from users as u where email = $1"#,
                email
            )
            .fetch_one(&mut conn)
            .await
            .unwrap();
            user
        }
    };
    log::debug!("Got user {user:?}. Logging in.");

    auth.login(&user).await.unwrap();

    log::debug!("Logged in the user: {user:?}");

    Redirect::to(format!("{}/", env::var("CLIENT_BASE_URL").unwrap()).as_str())
}
