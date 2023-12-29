use axum::extract::{DefaultBodyLimit, Multipart, Query};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{Request, StatusCode, Uri},
    response::IntoResponse,
    routing::{delete, get, post},
    BoxError, Json, Router,
};
use axum_login::login_required;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::{io::Error, os::unix::prelude::MetadataExt};
use tokio_util::io::StreamReader;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::auth::{AuthSession, Backend};
use chrono::{DateTime, Utc};
use futures::{Stream, TryStreamExt};
use tokio::fs::OpenOptions;
use tokio::{
    fs::{metadata, read_dir},
    io::{self, BufWriter},
};

use crate::{AppState, FileInfo, UPLOADS_DIRECTORY};

pub fn bucket_routes() -> Router<AppState> {
    Router::new()
        .route("/*path", get(get_route))
        .route(
            "/*path",
            post(save_request).layer(DefaultBodyLimit::max(100_000_000)),
        )
        .route("/*path", delete(delete_request))
        .route_layer(login_required!(Backend))
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
    pub updated_by_email: String,
    pub bucket: String,
    pub file_name: String,
    pub full_path: String,
}

async fn get_dir(path: &String, pool: &Pool<Sqlite>) -> impl IntoResponse {
    let mut dir = read_dir(path).await.unwrap();
    let mut file_infos: Vec<FileInfo> = Vec::new();
    let path_split: Vec<&str> = path.split('/').collect();
    let bucket = path_split[2];
    let folder_meta: Vec<Metadata> =
        sqlx::query_as!(Metadata, "select u.email as updated_by_email, m.bucket, m.file_name, m.full_path from metadata as m join users as u on u.id = m.updated_by where bucket = $1", bucket)
            .fetch_all(pool)
            .await
            .unwrap();
    while let Ok(entry) = dir.next_entry().await {
        let Some(entry) = entry else {
            break;
        };
        let metadata = entry.metadata().await.unwrap();
        let modified_at: DateTime<Utc> = metadata.modified().unwrap().into();
        let updated_by = folder_meta
            .iter()
            .find(|f| f.file_name == entry.file_name().to_str().unwrap())
            .map(|m| m.updated_by_email.as_str());

        file_infos.push(FileInfo {
            name: String::from(entry.file_name().to_str().unwrap()),
            is_directory: metadata.is_dir(),
            size: metadata.size(),
            modified_at: modified_at.to_rfc3339(),
            updated_by: updated_by.unwrap_or("").to_string(),
        });
        file_infos.sort_by(|a, b| b.is_directory.cmp(&a.is_directory));
    }
    (StatusCode::OK, Json(file_infos))
}

#[derive(Deserialize)]
struct SaveQuery {
    part: Option<u32>,
    total_parts: Option<u32>,
}
async fn save_request(
    state: State<AppState>,
    AuthSession { user, .. }: AuthSession,
    Path(path): Path<String>,
    query: Query<SaveQuery>,
    multipart: Option<Multipart>,
) -> impl IntoResponse {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    if !is_file(&path) {
        return match tokio::fs::create_dir(path).await {
            Ok(_) => Ok(StatusCode::CREATED),
            Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
        };
    }
    let Some(part) = query.part else {
        return Err((StatusCode::BAD_REQUEST, "missing part field".to_string()));
    };
    let Some(total_parts) = query.total_parts else {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing total_parts field".to_string(),
        ));
    };
    let path_split: Vec<&str> = path.split('/').collect();
    let bucket = path_split[2];
    let path = path_split.join("/");
    let file_name = path_split[path_split.len() - 1];
    if part == 1 {
        let exists = tokio::fs::try_exists(&path)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if exists {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }
    let Some(mut multipart) = multipart else {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing multipart form".to_string(),
        ));
    };
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap() {
            "data" => {
                stream_to_file(&path, field).await?;
            }
            _ => (),
        }
    }
    if part == total_parts {
        let user = user.unwrap();
        sqlx::query!("insert or replace into metadata (updated_by, bucket, file_name, full_path) values ($1, $2, $3, $4)", user.id, bucket, file_name, path)
            .execute(&state.pool).await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "error saving metadata".to_string(),
                )
            })?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_request(
    state: State<AppState>,
    Path(path): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, path);
    if let Ok(_) = tokio::fs::read_dir(&path).await {
        return match tokio::fs::remove_dir_all(&path).await {
            Ok(_) => Ok(StatusCode::NO_CONTENT),
            Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
        };
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

        tracing::debug!("writing to: {}", &path);
        // Create the file. `File` implements `AsyncWrite`.
        let path = std::path::Path::new(path);
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?;
        let mut file = BufWriter::new(file);

        // Copy the body into the file.
        io::copy(&mut body_reader, &mut file).await?;

        Ok::<_, Error>(())
    }
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

async fn serve_file(path: &str, uri: &Uri) -> impl IntoResponse {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    match ServeFile::new(path).oneshot(req).await {
        Ok(res) => Ok((StatusCode::OK, res)),
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
