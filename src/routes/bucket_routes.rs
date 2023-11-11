use axum::{
    body::{Body, Bytes},
    extract::{BodyStream, Path, State},
    http::{Request, Uri},
    response::IntoResponse,
    routing::get,
    BoxError, Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::{io::Error, os::unix::prelude::MetadataExt};
use tokio_util::io::StreamReader;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use axum::body::boxed;
use chrono::{DateTime, Utc};
use futures::{Stream, TryStreamExt};
use reqwest::StatusCode;
use tokio::{
    fs::{metadata, read_dir, File},
    io::{self, BufWriter},
};

use crate::{AppState, FileInfo, User, UPLOADS_DIRECTORY};

pub fn bucket_routes() -> Router<AppState> {
    Router::new().route(
        "/*path",
        get(get_route).post(save_request).delete(delete_request),
    )
}

async fn get_route(
    state: State<AppState>,
    Path(path): Path<String>,
    uri: Uri,
) -> impl IntoResponse {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    let Ok(meta) = metadata(&path).await else {
        return Err((StatusCode::BAD_REQUEST, "Invalid path".to_string()));
    };

    if meta.is_dir() {
        Ok(get_dir(&path, &state.pool).await.into_response())
    } else {
        Ok(serve_file(&path, &uri).await.into_response())
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: i64,
    pub created_by: Option<i64>,
    pub created_by_email: String,
    pub bucket: String,
    pub file_name: String,
    pub full_path: String,
}
async fn get_dir(path: &String, pool: &Pool<Sqlite>) -> impl IntoResponse {
    let mut dir = read_dir(path).await.unwrap();
    let mut file_infos: Vec<FileInfo> = Vec::new();
    let path_split: Vec<&str> = path.split('/').collect();
    let bucket = path_split[1];
    let folder_meta: Vec<Metadata> =
        sqlx::query_as!(Metadata, "select m.id, m.created_by, u.email as created_by_email, m.bucket, m.file_name, m.full_path from metadata as m join users as u on u.id = m.created_by where bucket = $1", bucket)
            .fetch_all(pool)
            .await
            .unwrap();
    while let Ok(entry) = dir.next_entry().await {
        let Some(entry) = entry else {
            break;
        };
        let metadata = entry.metadata().await.unwrap();
        let modified_at: DateTime<Utc> = metadata.modified().unwrap().into();
        let created_by = folder_meta
            .iter()
            .find(|f| f.file_name == entry.file_name().to_str().unwrap())
            .unwrap_or(&Metadata {
                id: 0,
                created_by: None,
                created_by_email: String::new(),
                bucket: String::new(),
                file_name: String::new(),
                full_path: String::new(),
            })
            .created_by_email
            .clone();
        file_infos.push(FileInfo {
            name: String::from(entry.file_name().to_str().unwrap()),
            is_directory: metadata.is_dir(),
            size: metadata.size(),
            modified_at: modified_at.to_rfc3339(),
            created_by,
        });
        file_infos.sort_by(|a, b| b.is_directory.cmp(&a.is_directory));
    }
    (StatusCode::OK, Json(file_infos))
}
async fn save_request(
    state: State<AppState>,
    Extension(user): Extension<User>,
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
    match stream_to_file(path.as_str(), body).await {
        Ok(result) => {
            let path_split: Vec<&str> = path.split('/').collect();
            let path_split = path_split[1..].to_vec();
            let path = path_split.join("/");
            let bucket = path_split[0];
            let file_name = path_split[path_split.len() - 1];
            sqlx::query!("insert or replace into metadata (created_by, bucket, file_name, full_path) values ($1, $2, $3, $4)", user.id, bucket, file_name, path)
            .execute(&state.pool).await.unwrap();
            return Ok(result);
        }
        Err(err) => Err(err),
    }
}
async fn delete_request(
    state: State<AppState>,
    Path(path): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    if let Ok(_) = tokio::fs::read_dir(&path).await {
        match tokio::fs::remove_dir_all(&path).await {
            Ok(_) => return Ok(StatusCode::NO_CONTENT),
            Err(error) => return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
        }
    }
    if let Err(error) = tokio::fs::remove_file(&path).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string()));
    }
    sqlx::query!("delete from metadata where full_path = $1", path)
        .execute(&state.pool)
        .await
        .unwrap();
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
    let path_split = path.split('/');
    let path = path_split.last().unwrap();
    let split: Vec<&str> = path.split('.').collect();
    split.len() > 1
}
