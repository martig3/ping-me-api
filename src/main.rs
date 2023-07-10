mod routes;

use crate::routes::routes;
use axum::body::boxed;

use axum::http::{header, HeaderValue, Method};

use axum::Extension;
use axum::{body::Bytes, Router};
use axum_login::axum_sessions::async_session::MemoryStore;

use axum_login::axum_sessions::SameSite;
use axum_login::axum_sessions::SessionLayer;
use axum_login::secrecy::SecretVec;
use axum_login::AuthLayer;
use axum_login::AuthUser;
use axum_login::RequireAuthorizationLayer;
use axum_login::SqliteStore;

use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

use sqlx::SqlitePool;
use std::env;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit, ServiceBuilderExt,
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileInfo {
    name: String,
    is_directory: bool,
    size: u64,
    modified_at: String,
}

#[derive(Clone)]
pub struct AppState {
    pool: SqlitePool,
}

#[derive(Clone, PartialEq, PartialOrd, sqlx::Type, Debug, Default)]
pub enum Role {
    #[default]
    User,
    Admin,
}

#[derive(Debug, Default, Clone, sqlx::FromRow)]
pub struct User {
    id: i64,
    password_hash: String,
    name: String,
    email: String,
    role: Role,
    avatar_url: Option<String>,
    discord_id: Option<String>,
}
impl AuthUser<i64> for User {
    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }
}

impl AuthUser<i64, Role> for User {
    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }

    fn get_role(&self) -> Option<Role> {
        Some(self.role.clone())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserInvite {
    id: i64,
    user_id: Option<i64>,
    email: String,
}
type AuthContext = axum_login::extractors::AuthContext<i64, User, SqliteStore<User>>;
type RequireAuth = RequireAuthorizationLayer<i64, User, Role>;
const UPLOADS_DIRECTORY: &str = "uploads";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "mert-bucket-api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = MemoryStore::new();
    let session_layer = SessionLayer::new(session_store, &secret)
        .with_secure(false)
        .with_same_site_policy(SameSite::Lax);
    let pool = SqlitePool::connect(&env::var("DATABASE_URL").expect("Expected DATABASE_URL"))
        .await
        .unwrap();
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Error running migrations");

    let user_store = SqliteStore::<User>::new(pool.clone());
    let auth_layer = AuthLayer::new(user_store, &secret);
    let oauth_client = build_discord_oauth_client();

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();
    let cors = CorsLayer::new()
        .allow_headers(vec![
            header::ACCEPT,
            header::ACCEPT_LANGUAGE,
            header::AUTHORIZATION,
            header::CONTENT_LANGUAGE,
            header::CONTENT_TYPE,
            header::VARY,
        ])
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::CONNECT,
            Method::PATCH,
            Method::TRACE,
        ])
        .allow_credentials(true)
        .allow_origin([
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
            "http://localhost:4173".parse::<HeaderValue>().unwrap(),
            "https://discord.com".parse::<HeaderValue>().unwrap(),
        ]);
    let middleware = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers.clone())
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros))
        )
        .layer(TimeoutLayer::new(Duration::from_secs(60 * 60 * 12)))
        .layer(cors)
        // Box the response body so it implements `Default` which is required by axum
        .map_response_body(boxed)
        .compression()
        .insert_response_header_if_not_present(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

    let shared_state = AppState { pool };

    let app = Router::new()
        .nest("/api", routes())
        .layer(middleware)
        .layer(auth_layer)
        .layer(session_layer)
        .layer(Extension(oauth_client))
        .with_state(shared_state);

    let host = matches!(env::var("ENV").as_deref(), Ok("prd"))
        .then_some([0, 0, 0, 0])
        .unwrap_or([127, 0, 0, 1]);
    let addr = SocketAddr::from((host, 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn build_discord_oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = format!(
        "{}/api/auth/discord/callback",
        env::var("BASE_URL").unwrap()
    );

    let auth_url =
        AuthUrl::new("https://discord.com/api/oauth2/authorize?response_type=code".to_string())
            .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://discord.com/api/oauth2/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}
