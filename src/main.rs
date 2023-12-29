mod auth;
mod errors;
mod routes;

use crate::auth::Backend;
use crate::routes::routes;
use axum::body::Bytes;
use axum::error_handling::HandleErrorLayer;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::{BoxError, Router};
use std::env;

use axum_login::tower_sessions::cookie::SameSite;
use axum_login::tower_sessions::{Expiry, SessionManagerLayer};
use axum_login::AuthManagerLayerBuilder;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use sqlx::SqlitePool;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit, ServiceBuilderExt,
};
use tower_sessions::SqliteStore;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileInfo {
    name: String,
    is_directory: bool,
    size: u64,
    modified_at: String,
    updated_by: String,
}

#[derive(Clone)]
pub struct AppState {
    pool: SqlitePool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserInvite {
    id: i64,
    user_id: Option<i64>,
    email: String,
}

const UPLOADS_DIRECTORY: &str = "data/uploads";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "bukkit-api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = SqlitePool::connect(&env::var("DATABASE_URL").expect("Expected DATABASE_URL"))
        .await
        .unwrap();
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Error running migrations");

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
            env::var("CLIENT_BASE_URL")
                .unwrap_or("http://localhost:5173".to_string())
                .parse::<HeaderValue>()
                .unwrap(),
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
        .compression()
        .insert_response_header_if_not_present(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

    let shared_state = AppState { pool: pool.clone() };
    // Session layer.
    //
    // This uses `tower-sessions` to establish a layer that will provide the session
    // as a request extension.
    let session_store = SqliteStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .expect("error running migrations for tower_sessions");
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
        .with_expiry(Expiry::OnInactivity(time::Duration::hours(1)));

    // Auth service.
    //
    // This combines the session layer with our backend to establish the auth
    // service which will provide the auth session as a request extension.
    let backend = Backend::new(pool.clone(), oauth_client);
    let auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(AuthManagerLayerBuilder::new(backend, session_layer).build());
    let app = Router::new()
        .nest("/api", routes())
        .layer(middleware)
        .layer(auth_service)
        .with_state(shared_state);

    let host = matches!(env::var("ENV").as_deref(), Ok("prd"))
        .then_some("0.0.0.0")
        .unwrap_or("127.0.0.1");
    let port = env::var("PORT").unwrap_or("3000".to_string());
    let port = port.parse::<u32>().expect("PORT should be a valid number");
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}"))
        .await
        .unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
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
