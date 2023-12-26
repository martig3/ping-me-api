use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use axum_login::permission_required;
use serde::Deserialize;
use tokio::fs::{metadata, read_dir};

use crate::auth::Backend;
use crate::{routes::bucket_routes::Metadata, AppState, UPLOADS_DIRECTORY};

#[derive(Debug, Deserialize)]
struct SearchRequest {
    search: String,
}

pub fn buckets_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_buckets))
        .route("/:name/search", get(get_bucket_search))
        .route_layer(permission_required!(Backend, "protected.read",))
        .route("/:name", delete(delete_bucket))
        .route_layer(permission_required!(Backend, "protected.delete",))
        .route("/:name", put(create_bucket))
        .route_layer(permission_required!(Backend, "protected.write",))
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

async fn create_bucket(Path(name): Path<String>) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, name);
    match tokio::fs::create_dir(path).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
    }
}

async fn delete_bucket(Path(name): Path<String>) -> Result<StatusCode, (StatusCode, String)> {
    let path = format!("{}/{}", &UPLOADS_DIRECTORY, name);
    match tokio::fs::remove_dir_all(path).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string())),
    }
}

async fn get_bucket_search(
    state: State<AppState>,
    Path(bucket_name): Path<String>,
    Query(query): Query<SearchRequest>,
) -> impl IntoResponse {
    let like = format!("%{}%", query.search);
    let results: Vec<Metadata> = sqlx::query_as!(Metadata, "select m.id, m.created_by, u.email as created_by_email, m.bucket, m.file_name, m.full_path from metadata as m join users as u on u.id = m.created_by where m.file_name like $1 order by m.file_name", like, )
        .fetch_all(&state.pool)
        .await
        .unwrap();
    // cant do an AND statement with query_as! macro for some reason so we filter it out here
    let results: Vec<Metadata> = results
        .into_iter()
        .filter(|m| m.bucket == bucket_name)
        .collect();
    Json(results)
}
