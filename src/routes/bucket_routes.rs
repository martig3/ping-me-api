use axum::{
    body::{Body, Bytes},
    extract::{BodyStream, Path},
    http::{Request, Uri},
    response::IntoResponse,
    routing::get,
    BoxError, Json, Router,
};
use std::{io::Error, os::unix::prelude::MetadataExt};
use tokio_util::io::StreamReader;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use axum::body::boxed;
use axum_login::RequireAuthorizationLayer;
use chrono::{DateTime, Utc};
use futures::{Stream, TryStreamExt};
use reqwest::StatusCode;
use tokio::{
    fs::{metadata, read_dir, File},
    io::{self, BufWriter},
};

use crate::{AppState, FileInfo, Role, User, UPLOADS_DIRECTORY};

pub fn bucket_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_buckets))
        .route(
            "/*path",
            get(get_route).post(save_request).delete(delete_request),
        )
        .route_layer(RequireAuthorizationLayer::<i64, User, Role>::login())
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

// Save a `Stream` to a file
async fn stream_to_file<S, E>(path: &str, stream: S) -> Result<(), (StatusCode, String)>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Into<BoxError>,
{
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
