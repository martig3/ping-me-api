use axum::async_trait;
use axum_login::{AuthUser, AuthnBackend, AuthzBackend, UserId};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, url::Url, AuthorizationCode, CsrfToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, SqlitePool};
use std::{collections::HashSet, env};

use crate::{errors::BackendError, UserInvite};
#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub avatar: Option<String>,
    pub username: String,
    pub email: Option<String>,
    pub discriminator: String,
}

#[derive(Default, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub avatar_url: Option<String>,
    pub discord_id: Option<String>,
    pub access_token: String,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.email)
            .field("access_token", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.access_token.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub db: SqlitePool,
    pub client: BasicClient,
}

impl Backend {
    pub fn new(db: SqlitePool, client: BasicClient) -> Self {
        Self { db, client }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(vec![Scope::new("email".to_string())])
            .url()
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromRow)]
pub struct Permission {
    pub name: String,
}

impl From<&str> for Permission {
    fn from(name: &str) -> Self {
        Permission {
            name: name.to_string(),
        }
    }
}
#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Ensure the CSRF state has not been tampered with.
        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Process authorization code, expecting a token response back.
        let token_res = self
            .client
            .exchange_code(AuthorizationCode::new(creds.code))
            .request_async(async_http_client)
            .await
            .map_err(Self::Error::OAuth2)?;
        // Fetch user data from discord
        let client = reqwest::Client::new();
        let user_data = client
            // https://discord.com/developers/docs/resources/user#get-current-user
            .get("https://discordapp.com/api/users/@me")
            .bearer_auth(token_res.access_token().secret())
            .send()
            .await
            .map_err(Self::Error::Reqwest)?
            .json::<DiscordUser>()
            .await
            .map_err(Self::Error::Reqwest)?;
        log::debug!("Getting db connection");

        let Some(email) = user_data.email else {
            return Err(BackendError::NoEmail);
        };

        // Fetch the user and log them in
        log::debug!("Getting user");
        let user: Option<User> = sqlx::query_as!(User, r#"select u.id, u.name, u.email, u.access_token, u.avatar_url, u.discord_id from users as u where email = $1"#, email)
       .fetch_optional(&self.db)
       .await
       .unwrap();
        let user = match user {
            Some(user) => user,
            None => {
                let is_owner = &email == &env::var("OWNER_EMAIL").expect("Missing OWNER_EMAIL");
                if !is_owner {
                    let Some(_invite) = sqlx::query_as!(
                        UserInvite,
                        "select * from user_invites where email = $1",
                        email
                    )
                    .fetch_optional(&self.db)
                    .await
                    .unwrap() else {
                        return Err(BackendError::NoEmail);
                    };
                }

                let access_token = token_res.access_token().secret().clone();
                sqlx::query!(
               "insert into users (name, email, avatar_url, discord_id, access_token) values ($1, $2, $3, $4, $5);",
               user_data.username,
               email,
               user_data.avatar,
               user_data.id,
               access_token,
           )
           .execute(&self.db)
           .await
           .unwrap();
                let user: User = sqlx::query_as!(
               User,
               r#"select u.id, u.name, u.email, u.avatar_url, u.discord_id, u.access_token from users as u where email = $1"#,
               email
           )
           .fetch_one(&self.db)
           .await
           .unwrap();
                user
            }
        };

        Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Self::Error::Sqlx)?)
    }
}

#[async_trait]
impl AuthzBackend for Backend {
    type Permission = Permission;

    async fn get_group_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let permissions: Vec<Self::Permission> = sqlx::query_as!(
            Self::Permission,
            r#"
            select distinct permissions.name
            from users
            join users_groups on users.id = users_groups.user_id
            join groups_permissions on users_groups.group_id = groups_permissions.group_id
            join permissions on groups_permissions.permission_id = permissions.id
            where users.id = ?
            "#,
            user.id
        )
        .fetch_all(&self.db)
        .await
        .map_err(Self::Error::Sqlx)?;

        Ok(permissions.into_iter().collect())
    }
}
// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
