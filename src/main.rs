use axum::body::boxed;
use axum::body::Body;
use axum::extract::Query;
use axum::http::{header, HeaderValue, Method, Request, Uri};
use axum::response::Redirect;
use axum::routing::delete;
use axum::Extension;
use axum::{
    body::Bytes,
    extract::{BodyStream, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_login::axum_sessions::async_session::MemoryStore;
use axum_login::axum_sessions::extractors::ReadableSession;
use axum_login::axum_sessions::extractors::WritableSession;
use axum_login::axum_sessions::SameSite;
use axum_login::axum_sessions::SessionLayer;
use axum_login::secrecy::SecretVec;
use axum_login::AuthLayer;
use axum_login::AuthUser;
use axum_login::RequireAuthorizationLayer;
use axum_login::SqliteStore;
use futures::{Stream, TryStreamExt};
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use sqlx::SqlitePool;
use std::env;
use std::io::Error;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;
use std::{io, net::SocketAddr};
use tokio::fs::File;
use tokio::fs::{metadata, read_dir};
use tokio::io::BufWriter;
use tokio_util::io::StreamReader;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit, ServiceBuilderExt,
};
use tracing::log;
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

#[derive(Debug, Default, Clone, sqlx::FromRow)]
struct User {
    id: i64,
    password_hash: String,
    name: String,
    email: String,
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

#[derive(Debug, Default, Clone, sqlx::FromRow)]
struct UserInvite {
    id: i64,
    user_id: i64,
    invite_key: String,
    email: String,
    accepted: bool,
}

type AuthContext = axum_login::extractors::AuthContext<i64, User, SqliteStore<User>>;
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

    let bucket_routes = Router::new()
        .route("/", get(get_buckets))
        .route(
            "/*path",
            get(get_route).post(save_request).delete(delete_request),
        )
        .route_layer(RequireAuthorizationLayer::<i64, User>::login());
    let auth_routes = Router::new()
        .route("/logout", get(logout_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
        .route("/login", get(login_handler))
        .route("/discord/callback", get(oauth_callback_handler))
        .layer(Extension(oauth_client))
        .layer(Extension(pool.clone()));
    let user_routes = Router::new()
        .route("/me", get(user_info_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login());
    let api_routes = Router::new()
        .nest("/buckets", bucket_routes)
        .nest("/auth", auth_routes)
        .nest("/user", user_routes);

    let shared_state = AppState { pool };

    let app = Router::new()
        .nest("/api", api_routes)
        .layer(middleware)
        .layer(auth_layer)
        .layer(session_layer)
        .with_state(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_buckets() -> impl IntoResponse {
    let mut dir = read_dir(UPLOADS_DIRECTORY).await.unwrap();
    let mut buckets = Vec::new();
    while let Ok(entry) = dir.next_entry().await {
        let Some(entry) = entry else {
            break;
        };
        let path = entry.path();
        let metadata = metadata(&path).await.unwrap();
        if metadata.is_dir() {
            buckets.push(String::from(entry.file_name().to_str().unwrap()));
        }
    }
    (StatusCode::OK, Json(buckets))
}

async fn delete_request(Path(path): Path<String>) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    if let Ok(_) = tokio::fs::read_dir(&path).await {
        match tokio::fs::remove_dir_all(&path).await {
            Ok(_) => return Ok(StatusCode::NO_CONTENT),
            Err(error) => return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
        }
    }
    if let Err(error) = tokio::fs::remove_file(path).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn save_request(
    Path(path): Path<String>,
    body: BodyStream,
) -> Result<(), (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    if !is_file(&path) {
        match tokio::fs::create_dir(path).await {
            Ok(_) => return Ok(()),
            Err(error) => return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
        }
    }
    stream_to_file(path.as_str(), body).await
}

// Save a `Stream` to a file
async fn stream_to_file<S, E>(path: &str, stream: S) -> Result<(), (StatusCode, String)>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Into<BoxError>,
{
    // if !path_is_valid(path) {
    //     return Err((StatusCode::BAD_REQUEST, "Invalid path".to_owned()));
    // }

    async {
        // Convert the stream into an `AsyncRead`.
        let body_with_io_error = stream.map_err(|err| Error::new(io::ErrorKind::Other, err));
        let body_reader = StreamReader::new(body_with_io_error);
        futures::pin_mut!(body_reader);

        tracing::debug!("saving: {}", &path);
        // Create the file. `File` implements `AsyncWrite`.
        let path = std::path::Path::new(path);
        let mut file = BufWriter::new(File::create(path).await?);

        // Copy the body into the file.
        tokio::io::copy(&mut body_reader, &mut file).await?;

        Ok::<_, Error>(())
    }
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

async fn get_route(Path(path): Path<String>, uri: Uri) -> impl IntoResponse {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    let Ok(meta) = metadata(&path).await else {
        return Err((StatusCode::BAD_REQUEST, "Invalid path".to_string()));
    };

    if meta.is_dir() {
        Ok(get_dir(&path).await.into_response())
    } else {
        Ok(serve_file(&path, &uri).await.into_response())
    }
}

async fn get_dir(path: &String) -> impl IntoResponse {
    let mut dir = read_dir(path).await.unwrap();
    let mut file_infos: Vec<FileInfo> = Vec::new();
    while let Ok(entry) = dir.next_entry().await {
        let Some(entry) = entry else {
            break;
        };
        let metadata = entry.metadata().await.unwrap();
        let modified_at: DateTime<Utc> = metadata.modified().unwrap().into();
        file_infos.push(FileInfo {
            name: String::from(entry.file_name().to_str().unwrap()),
            is_directory: metadata.is_dir(),
            size: metadata.size(),
            modified_at: modified_at.to_rfc3339(),
        });
        file_infos.sort_by(|a, b| b.is_directory.cmp(&a.is_directory));
    }
    (StatusCode::OK, Json(file_infos))
}

async fn serve_file(path: &str, uri: &Uri) -> impl IntoResponse {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    match ServeFile::new(path).oneshot(req).await {
        Ok(res) => Ok((StatusCode::OK, res.map(boxed))),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", err),
        )),
    }
}

fn is_file(path: &str) -> bool {
    let path_split = path.split("/");
    let path = path_split.last().unwrap();
    let split: Vec<&str> = path.split(".").collect();
    split.len() > 1
}

fn build_discord_oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = "http://localhost:3000/api/auth/discord/callback".to_string();

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

async fn logout_handler(mut auth: AuthContext) -> impl IntoResponse {
    dbg!("Logging out user: {}", &auth.current_user);
    auth.logout().await
}
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
async fn oauth_callback_handler(
    mut auth: AuthContext,
    Query(query): Query<AuthRequest>,
    Extension(pool): Extension<SqlitePool>,
    Extension(oauth_client): Extension<BasicClient>,
    session: ReadableSession,
) -> impl IntoResponse {
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
        return Redirect::to("/protected");
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
    let user: Option<User> = sqlx::query_as!(User, "select * from users where email = $1", email)
        .fetch_optional(&mut conn)
        .await
        .unwrap();
    let user = match user {
        Some(user) => user,
        None => {
            if &email != &env::var("OWNER_EMAIL").expect("Missing OWNER_EMAIL") {
                let Some(_invite) = sqlx::query_as!( UserInvite, "select * from user_invites where email = $1",
                    email
                )
                .fetch_optional(&mut conn)
                .await
                .unwrap() else {
                    return Redirect::to("/no-invite");
                };
            }

            sqlx::query!(
                "insert into users (password_hash, name, email, avatar_url, discord_id) values ($1, $2, $3, $4, $5);",
                user_data.username,
                user_data.username,
                email,
                user_data.avatar,
                user_data.id,
            )
            .execute(&mut conn)
            .await
            .unwrap();
            let user: User = sqlx::query_as!(User, "select * from users where email = $1", email)
                .fetch_one(&mut conn)
                .await
                .unwrap();
            user
        }
    };
    log::debug!("Got user {user:?}. Logging in.");

    auth.login(&user).await.unwrap();

    log::debug!("Logged in the user: {user:?}");

    Redirect::to("http://localhost:5173/")
}

#[derive(Serialize, Deserialize)]
struct UserInfo {
    name: String,
    email: String,
    discord_avatar: String,
}
async fn user_info_handler(Extension(user): Extension<User>) -> impl IntoResponse {
    Json(UserInfo {
        name: user.name,
        email: user.email,
        discord_avatar: format!(
            "https://cdn.discordapp.com/avatars/{}/{}",
            user.discord_id.unwrap_or_default(),
            user.avatar_url.unwrap_or_default()
        ),
    })
}
