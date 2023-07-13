use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use axum_login::RequireAuthorizationLayer;
use serde::Deserialize;

use crate::{routes::bucket_routes::Metadata, AppState, User};
#[derive(Debug, Deserialize)]
struct SearchRequest {
    search: String,
}
pub fn search_routes() -> Router<AppState> {
    Router::new()
        .route("/bucket/:name", get(get_bucket_search))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
}
async fn get_bucket_search(
    state: State<AppState>,
    Path(bucket_name): Path<String>,
    Query(query): Query<SearchRequest>,
) -> impl IntoResponse {
    let like = format!("%{}%", query.search);
    println!("{}", like);
    println!("{}", bucket_name);
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
