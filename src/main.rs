use axum::body::boxed;
use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, Uri};
use axum::routing::delete;
use axum::{
    body::Bytes,
    extract::{BodyStream, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    BoxError, Json, Router,
};
use futures::{Stream, TryStreamExt};

use chrono::{DateTime, Utc};
use serde::Serialize;
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
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
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

const UPLOADS_DIRECTORY: &str = "uploads";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "mert-bucket-api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

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
        .allow_origin([
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
            "http://localhost:4173".parse::<HeaderValue>().unwrap(),
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
        .route("/:bucket_name/*path", get(get_route))
        .route("/:bucket_name/*path", post(save_request_body))
        .route("/:bucket_name/*path", delete(delete_request));
    let api_routes = Router::new().nest("/buckets", bucket_routes);

    let app = Router::new().nest("/api", api_routes).layer(middleware);

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

async fn delete_request(
    Path(params): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}/{}", &UPLOADS_DIRECTORY, &params.0, &params.1);
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
// Handler that streams the request body to a file.
async fn save_request_body(
    Path(params): Path<(String, String)>,
    body: BodyStream,
) -> Result<(), (StatusCode, String)> {
    let path = format!("{}/{}/{}", &UPLOADS_DIRECTORY, &params.0, &params.1);
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

async fn get_route(Path(params): Path<(String, String)>, uri: Uri) -> impl IntoResponse {
    let path = format!("{}/{}{}", &UPLOADS_DIRECTORY, params.0, params.1);
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
//
// fn path_is_valid(path: &str) -> bool {
//     let path = std::path::Path::new(path);
//     let mut components = path.components().peekable();
//
//     if let Some(first) = components.peek() {
//         if !matches!(first, std::path::Component::Normal(_)) {
//             return false;
//         }
//     }
//
//     components.count() == 1
// }
